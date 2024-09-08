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
//#include <algorithm>
#include <sys/uio.h>

#include <cstdint>
#include <map>
#include "elftypes.hpp"
#include "elf.hpp"
#include "dbgtypes.hpp"
#include "dbg.hpp"
#include "disass.hpp"

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
    auto addr = entry.second->get_symbol_addr(sym);

    if (addr != 0) {
      return entry.second->get_symbol_size(sym);
    }
  }
  return 0;
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

std::string Debugger::get_file_from_addr(uint64_t addr) {
  std::string ret;
  auto entry = vmmap.begin();

  for (; entry != vmmap.end(); ++entry) {
    if (entry->contains(addr)) {
      break;
    }
  }
 
  if (entry == vmmap.end()) {
    //std::cout << "address not found" << std::endl; 
    return ret;
  }

  auto file = elf_table.find(entry->get_file());
  if (file == elf_table.end()) {
    //std::cout << "cant disassemble this region" << std::endl; 
    return ret;
  }
  return entry->get_file();
}

uint8_t *Debugger::get_bytes_from_file(std::string filename, uint64_t addr, uint32_t n) {
  auto file_entry = elf_table.find(filename);
 
  if (file_entry == elf_table.end()) {
    std::cout << "filename invalid" << std::endl;
    return NULL;
  }

  ELF *elf_ptr = file_entry->second;
  return elf_ptr->get_n_bytes_at_addr(addr, n);
}

uint8_t *Debugger::get_bytes_from_memory(uint64_t addr, uint32_t n) {
  if (WIFEXITED(status)) {
    std::cout << "Program is no longer beeing run" << std::endl; 
    return NULL;
  }

  uint8_t *ret = new uint8_t[n];

  struct iovec local_mem[1];
  struct iovec remote_mem[1];

  local_mem[0].iov_base = ret;
  local_mem[0].iov_len = n;

  remote_mem[0].iov_base = (void *)(addr);
  remote_mem[0].iov_len = n; 

  if (process_vm_readv(proc, local_mem, 1, remote_mem, 1, 0) != n) {
    delete[] ret;
    return NULL;
  }

  return ret;
}


Debugger::Debugger (const char *filename) : filename(filename) {
  elf = new ELF(filename);

  if (elf->pie()) {
    std::cout << "File is PIE" << std::endl;
  } else {
    std::cout << "No PIE" << std::endl;
  }

  switch (elf->get_machine()) {
    case EM_X86_64:
      arch = ARCH_X86_64;
      break;
    case EM_386:
      arch = ARCH_X86_32;
      break;
    default:
      arch = ARCH_UNDEF;
      break;
  }

  //base_addr = 0;

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

    /*
    if (elf->pie()) {
      base_addr = read_vmmap_base();
    }*/


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
 
  //base_addr = 0;

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

//////////////////////
//Breakpoint Functions
///////////////////////

void Debugger::set_breakpoint(unsigned long addr) {
  for (Breakpoint bp: breakpoints) {
    if (bp.get_addr() == addr) {
      return;
    }
  }

  std::string filename = get_file_from_addr(addr);

  uint8_t *bytes;

  if (filename.empty()) {
    bytes = get_bytes_from_memory(addr, 1);
  } else {
    bytes = get_bytes_from_file(filename, addr, 1);
  }

  if (bytes == NULL) {
    return;
  }

  char data = static_cast<char>(bytes[0]);

  delete[] bytes;

  //auto data = elf_file->get_byte_at_offset(offset);

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

////////////////////
// DISASSEMBLE
////////////////////
std::vector<Instruction> Debugger::disassemble(uint64_t addr, size_t n) { //disas_mode mode) {
  std::vector<Instruction> instructions;

  std::string filename = get_file_from_addr(addr);
  uint8_t *bytes;

  if (filename.empty()) {
    std::cout << "WARNING: disassembling section that is not a file" << std::endl;
    bytes = get_bytes_from_memory(addr, n);
  } else {
    bytes =  get_bytes_from_file(filename, addr, n); 
  }

  if (bytes == NULL) {
    return instructions;
  }

  
  switch (arch) {
    case ARCH_X86_64:
      instructions = disassemble_x86_64(addr, bytes, n);
      break;
    case ARCH_X86_32:
      instructions = disassemble_i386(addr, bytes, n);
      break;
    default: 
      std::cout << "[Error] No valid architecture" << std::endl;
      return instructions;
  }

  delete[] bytes;

  //for (auto instr = instructions.begin();  instr != instructions.end(); ++instr) {
  for (auto& instr : instructions) {
    instr.set_prefix("   ");

    if (instr.get_addr() == regs.rip) {
      instr.set_prefix(" > ");
    }

    for (auto bp : breakpoints) {
      if (bp.get_addr() == instr.get_addr()) {
        instr.set_prefix(" * ");
        break;
      } 
    }
  } 

  return instructions;
}

std::vector<Instruction> Debugger::disassemble(std::string symbol) {
  std::vector<Instruction> instructions;

  uint64_t addr = get_symbol_addr(symbol);
  if (addr == 0) {
    std::cout << "Symbol not found" << std::endl;
    return instructions;
  }

  uint32_t size = get_symbol_size(symbol);

  instructions = disassemble(addr, size);
  std::cout << instructions[0].str() << std::endl;
  return instructions;
}

/////////////////////
// READM FROM MEMORY
////////////////////

uint8_t *Debugger::get_bytes(uint64_t addr, size_t n) {
  std::string filename = get_file_from_addr(addr);
  uint8_t *bytes; 

  if (filename.empty()) {
    std::cout << "reading from mem" << std::endl;
    bytes = get_bytes_from_memory(addr, n);
  } else {
    bytes = get_bytes_from_file(filename, addr, n);
  }

  if (bytes == NULL) {
    return NULL;
  }

  return bytes;
}

std::vector<uint64_t> Debugger::get_long(uint64_t addr, size_t n) {
  std::vector<uint64_t> ret; 
  auto bytes = get_bytes(addr, n*8);

  if (bytes == NULL) {
    return ret;
  }


 for (size_t i = 0; i < n; i++) {
    uint64_t addr = static_cast<uint64_t>(bytes[i*8]);
    addr += static_cast<uint64_t>(bytes[i*8+1]) << 8;
    addr += static_cast<uint64_t>(bytes[i*8+2]) << 2*8;
    addr += static_cast<uint64_t>(bytes[i*8+3]) << 3*8;
    addr += static_cast<uint64_t>(bytes[i*8+4]) << 4*8;
    addr += static_cast<uint64_t>(bytes[i*8+5]) << 5*8;
    addr += static_cast<uint64_t>(bytes[i*8+6]) << 6*8;
    addr += static_cast<uint64_t>(bytes[i*8+7]) << 7*8;


    ret.emplace_back(addr);
  }

  delete[] bytes;

  return ret;
}

std::vector<uint32_t> Debugger::get_word(uint64_t addr, size_t n) {
  std::vector<uint32_t> ret; 
  auto bytes = get_bytes(addr, n*4);

  if (bytes == NULL) {
    return ret;
  }


 for (size_t i = 0; i < n; i++) {
    uint32_t addr = static_cast<uint32_t>(bytes[i*4]);
    addr += bytes[i*4+1] << 8;
    addr += bytes[i*4+2] << 2*8;
    addr += bytes[i*4+3] << 3*8;


    ret.emplace_back(addr);
  }

  delete[] bytes;

  return ret;
}

//////////////////////
// print functions
/////////////////////
uint64_t Debugger::get_rip() {
  return regs.rip;
}


void Debugger::print_regs() {
  std::cout << "rsp: 0x" << std::hex << regs.rsp << std::endl;
  std::cout << "rax: 0x" << std::hex << regs.rax << std::endl;
  std::cout << "rbp: 0x" << std::hex << regs.rbp << std::endl;
  std::cout << "rip: 0x" << std::hex << regs.rip << std::endl;
}

void Debugger::print_vmmap() {
  for (auto& entry: vmmap) {
    std::cout << entry.str() << std::endl;
  }
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

