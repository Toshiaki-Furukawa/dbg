#include <string>
#include <iostream>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <vector>
#include <signal.h>

#include <sstream>
#include <fstream>
#include <algorithm>

#include <cstdint>
#include <map>
#include "elftypes.hpp"
#include "elf.hpp"
#include "dbgtypes.hpp"
#include "dbg.hpp"

bool is_elf(std::string file) {
  std::ifstream file_content(file, std::ios::binary | std::ios::ate);

  if (!file_content.is_open()) {
    return false;
  }

  char magic[4] = {'\xf7', 'E', 'L', 'F'}; 

  for (int i = 0; i < 0; i++) {
    char tmp;
    file_content.get(tmp);
    if (tmp != magic[i]) {
      file_content.close();
      return false;
    }
  }

  file_content.close();
  return true;
}

void Debugger::enable_breakpoint(Breakpoint *bp) {
  if (WIFEXITED(status)) {
    return;
  }

  auto data = ptrace(PTRACE_PEEKDATA, proc, bp->get_addr(), NULL);
  auto mod_data = ((data & ~0xff) | 0xcc);
    
  ptrace(PTRACE_POKEDATA, proc, bp->get_addr(), mod_data);
  bp->enable();
}

void Debugger::disable_breakpoint(Breakpoint *bp) {
  if (WIFEXITED(status)) {
    return;
  }

  auto data = ptrace(PTRACE_PEEKDATA, proc, bp->get_addr(), NULL);
  auto orig_data = ((data & ~0xff) | bp->get_data());

  ptrace(PTRACE_POKEDATA, proc, bp->get_addr(), orig_data);

  bp->disable(); 
}

int Debugger::update_regs() {
  if (ptrace(PTRACE_GETREGS, proc, NULL, &regs) == -1) {
    std::cout << "could not load registers";
    return -1;
  } 
  return 1;
}

//  this function is useful to get a estimate of mappings, prior to reading vmmap
uint64_t Debugger::read_vmmap_base() {
  std::stringstream filename;
  filename << "/proc/" << proc << "/maps"; 

  std::ifstream vmmap_file(filename.str());

  if (!vmmap_file.is_open()) {
    std::cout << "could not open vmmaps file" << std::endl;
    return 0;
  }

  std::string base_addr_str;
  std::getline(vmmap_file, base_addr_str, ' ');
  vmmap_file.close();
  return std::stol(base_addr_str, NULL, 16);
}

void Debugger::read_vmmap() {
  std::stringstream filename;
  filename << "/proc/" << proc << "/maps"; 

  std::ifstream vmmap_file(filename.str());

  if (!vmmap_file.is_open()) {
    std::cout << "could not open vmmaps file" << std::endl;
  }

  vmmap.clear(); // Chage this just for testing
    
  for (std::string line; getline(vmmap_file, line); ) {
    MapEntry map(line);
    if (map.get_start() == 0) {
      continue;
    }

    vmmap.emplace_back(map);
  }
  vmmap_file.close();
}

Debugger::Debugger (const char *filename) : filename(filename) {
  elf = new ELF(filename);

  if (elf->pie()) {
    std::cout << "File is PIE" << std::endl;
  } else {
    std::cout << "No PIE" << std::endl;
  }

  base_addr = 0;

  proc = fork();
  if (proc == -1) {
    std::cout << "Error while forking" << std::endl;  
    exit(-1);
  }
  
  if (proc == 0) {
    personality(ADDR_NO_RANDOMIZE);

    ptrace(PTRACE_TRACEME, proc, NULL, NULL);

    execl(filename, filename, NULL, NULL);
  } else {
    waitpid(proc, &status, 0);
    ptrace(PTRACE_SETOPTIONS, proc, NULL, PTRACE_O_EXITKILL);

    if (elf->pie()) {
      base_addr = read_vmmap_base();
    }


    // get memory mapping of child process
    read_vmmap();

    // read files that are in memory
    for (auto& entry: vmmap)  {
      auto filename = entry.get_file();

      if (is_elf(filename) && (elf_table.find(filename) == elf_table.end())) {
        ELF *vmmap_elf_file = new ELF(filename.c_str());
        vmmap_elf_file->rebase(entry.get_start());

        elf_table.insert(std::pair(filename, vmmap_elf_file));
      }
    }

    return;
  }
}

Debugger::~Debugger() {
  delete elf;
  for (auto it : elf_table) {
    delete it.second;
  }

  elf_table.clear();
}

void Debugger::reset() {          // WARNING: not working
  kill(proc, SIGKILL);
  waitpid(proc, &status, 0);

  if (WIFSIGNALED(status)) {
    std::cout << "tracee killed" << std::endl;
  }

  if (elf->pie()) {
    std::cout << "File is PIE" << std::endl;
  } else {
    std::cout << "No PIE" << std::endl;
  }
 
  base_addr = 0;

  proc = fork();
  if (proc == -1) {
    std::cout << "Error while forking new process" << std::endl;
    exit(-1);
  }

  if (proc == 0) {
    personality(ADDR_NO_RANDOMIZE);

    ptrace(PTRACE_TRACEME, proc, NULL, NULL);

    execl(filename, filename, NULL, NULL);
  } else {
    waitpid(proc, &status, 0);
    ptrace(PTRACE_SETOPTIONS, proc, NULL, PTRACE_O_EXITKILL);

    if (elf->pie()) {
      base_addr = read_vmmap_base();
    }

    //std::cout << "reading vmmap" << std::endl;
    read_vmmap();

    update_regs();

    for (Breakpoint bp: breakpoints) {
      enable_breakpoint(&bp);
    }

    return;
  }
}

int Debugger::cont() {
  ptrace(PTRACE_CONT, proc, NULL, NULL);

  waitpid(proc, &status, 0);
  if (WIFEXITED(status)) {
    return 0;
  }

  read_vmmap();    

  update_regs();

  if (ptrace(PTRACE_GETSIGINFO, proc, NULL, &signal)  == -1) {
    std::cout << "cant decode signal..." << std::endl;
    return -1;
  }

  if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
    for (Breakpoint bp: breakpoints) {
      if (bp.get_addr() == regs.rip-1) {
        disable_breakpoint(&bp);
        regs.rip -= 1;

        if (ptrace(PTRACE_SETREGS, proc, NULL, &regs) == -1) {
          std::cout << "Error occured: could not set registers while handeling SIGTRAP" << std::endl;
        }

        single_step();

        enable_breakpoint(&bp);
        update_regs();
        break;
      }
    }
    return 1; 
  }  else {
    return -1;
  }  
}

void Debugger::print_regs() {
  std::cout << "rsp: 0x" << std::hex << regs.rsp << std::endl;
  std::cout << "rax: 0x" << std::hex << regs.rax << std::endl;
  std::cout << "rbp: 0x" << std::hex << regs.rbp << std::endl;
  std::cout << "rip: 0x" << std::hex << regs.rip << std::endl;
}


void Debugger::set_breakpoint(unsigned long addr) {
  for (Breakpoint bp: breakpoints) {
    if (bp.get_addr() == addr) {
      return;
    }
  }

  auto entry = vmmap.begin();
  for (; entry != vmmap.end(); ++entry) {
    if (entry->contains(addr)) {
      break;
    }
  }

  auto file = elf_table.find(entry->get_file());
  if (file == elf_table.end()) {
    std::cout << "cant disassemble this region" << std::endl; 
    return;
  }
 
  if (entry == vmmap.end()) {
    std::cout << "address not found" << std::endl; 
    return;
  }

  auto elf_file = file->second;
  uint64_t offset = (addr - entry->get_start()) + entry->get_offset();

  auto data = elf_file->get_byte_at_offset(offset);

  Breakpoint bp = Breakpoint(addr, data);
  enable_breakpoint(&bp);

  breakpoints.emplace_back(Breakpoint(addr, data)); 
}

void Debugger::delete_breakpoint(uint32_t idx) {
  if (idx >= breakpoints.size()) {
    return;
  }

  disable_breakpoint(&(breakpoints[idx]));
    
  breakpoints.erase(breakpoints.begin()+idx); 
}

void Debugger::enable_bp(unsigned int idx) {
  enable_breakpoint(&(breakpoints[idx]));
}
      
void Debugger::disable_bp(unsigned int idx) {
  disable_breakpoint(&(breakpoints[idx]));
}

void Debugger::disassemble(uint64_t addr, size_t n, disas_mode mode) {
  std::vector<Instruction> instructions;
  // get correct memory segment
  auto entry = vmmap.begin();
  for (; entry != vmmap.end(); ++entry) {
    if (entry->contains(addr)) {
      break;
    }
  }
 
  if (entry == vmmap.end()) {
    std::cout << "address not found" << std::endl; 
    return;
  }

  auto file = elf_table.find(entry->get_file());
  if (file == elf_table.end()) {
    std::cout << "cant disassemble this region" << std::endl; 
    return;
  }

  auto elf_file = file->second;
  uint64_t offset = (addr - entry->get_start()) + entry->get_offset();

  std::cout << "offsset: " << offset << std::endl;

  switch (mode) {
    case DISAS_MODE_WORD:
      instructions = elf_file->disassemble_words(addr, offset, n);
      break;
    case DISAS_MODE_BYTE:
      instructions = elf_file->disassemble_bytes(addr, offset, n);
      break;
    default: 
      std::cout << "[Warning] No valid mode for disassembly" << std::endl;
      instructions = elf_file->disassemble_bytes(addr, offset, n);
      break;
  }

  std::string prefix = "   ";

  for (auto instr : instructions) {
    if (instr.address() == regs.rip) {
      prefix.assign(" > ");
    }
    for (auto bp : breakpoints) {
      if (bp.get_addr() == instr.address()) {
        prefix.assign(" * ");
        break;
      } 
    }
    std::cout << prefix << instr.str() << std::endl;
    prefix.assign("   ");
  }
}

void Debugger::print_vmmap() {
  for (auto& entry: vmmap) {
    std::cout << entry.str() << std::endl;
  }
}

std::vector<uint64_t> Debugger::get_long(uint64_t addr, size_t n) {
  std::vector<uint64_t> ret; 
  if (WIFEXITED(status)) {
    std::cout << "program is no longer beeing run" << std::endl;
    return ret;
  }


  ret.reserve(n);
  for (size_t i = 0; i < n; i++) {
    uint64_t data = ptrace(PTRACE_PEEKDATA, proc, addr + i*8, NULL);
    ret.emplace_back(data);
  }

  return ret;
}

std::vector<uint32_t> Debugger::get_word(uint64_t addr, size_t n) {
  std::vector<uint32_t> ret; 
  if (WIFEXITED(status)) {
    std::cout << "program is no longer beeing run" << std::endl;
    return ret;
  }

  ret.reserve(2*n);
  for (size_t i = 0; i < n; i++) {
    uint64_t data = ptrace(PTRACE_PEEKDATA, proc, addr + i*8, NULL);
    //uint32_t lower = static_cast<uint32_t>(data & 0xffffffff);
    auto upper = static_cast<uint32_t>((data & ~static_cast<uint64_t>(0xffffffff)) >> 8*4);
    auto lower = static_cast<uint32_t>(data & 0xffffffff);

    ret.emplace_back(lower);
    ret.emplace_back(upper);
  }

  return ret;
}

uint64_t Debugger::get_symbol_addr(std::string sym) {
  for (auto& entry : elf_table) {
    auto addr = entry.second->get_symbol_addr(sym);

    if (addr != 0) {
      return addr;
    }
  }
  return 0;
}

uint32_t Debugger::get_symbol_size(std::string sym) {
  for (auto& entry : elf_table) {
    auto size = entry.second->get_symbol_size(sym);

    if (size != 0) {
      return size;
    }
  }
  return 0;
}

void Debugger::single_step() {
  if (WIFEXITED(status)) {
    return;
  }

  if (ptrace(PTRACE_SINGLESTEP, proc, NULL, NULL)) {
    std::cout << "single step failed" << std::endl;
    return;
  }

  waitpid(proc, &status, 0);
  update_regs();
}

void Debugger::list_breakpoints() {
  for (size_t i = 0; i < breakpoints.size(); i++) {
    std::cout << "brekpoint nr. " << i << " at " << std::hex << breakpoints[i].get_addr() << std::endl;
  }
}

void Debugger::print_symbols() {
  for (auto& entry : elf_table) {
    entry.second->print_symtab();
  }
}

void Debugger::print_sections() {
  elf->print_sections();
}

