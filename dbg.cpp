#include <string>
#include <iostream>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <vector>
#include <signal.h>
#include <filesystem>

#include <sstream>
#include <fstream>
#include <sys/uio.h>

#include <cstdint>
#include <map>
#include "elftypes.hpp"
#include "elf.hpp"
#include "dbgtypes.hpp"
#include "dbg.hpp"
#include "disass.hpp"
#include "fmt.hpp"

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

uint64_t Debugger::get_symbol_addr(std::string sym) {
  for (const auto& entry : elf_table) {
    auto addr = entry.second->get_symbol_addr(sym);

    if (addr != 0) {
      return addr;
    }
  }
  return 0;
}

uint32_t Debugger::get_symbol_size(std::string sym) {
  for (const auto& entry : elf_table) {
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

  const ELF *elf_ptr = file_entry->second;
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
  elf = NULL;
  regs = NULL;

  if (!std::filesystem::exists(filename)) {
    std::cout << "file does not exist" << std::endl;
    return;
  }

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
    std::cout << "hi "  << proc << std::endl;
    waitpid(proc, &status, 0);
    ptrace(PTRACE_SETOPTIONS, proc, NULL, PTRACE_O_EXITKILL);
    std::cout << "tracing process pid: " << proc << std::endl;

    // get memory mapping of child process
    std::cout << "reading vmmap" << std::endl;
    read_vmmap();

    // read files that are in memory
    for (const auto& entry: vmmap)  {
      auto filename = entry.get_file();

      if (is_elf(filename) && (elf_table.find(filename) == elf_table.end())) {
        ELF *vmmap_elf_file = new ELF(filename.c_str());
        vmmap_elf_file->rebase(entry.get_start());

        if (elf == NULL) {
          elf = vmmap_elf_file;
        }

        elf_table.insert(std::pair(filename, vmmap_elf_file));
      }
    }
    if (elf == NULL) {
      return;
    }

    switch (elf->get_machine()) {
    case EM_X86_64:
      std::cout << "Arch: x86-64" << std::endl;
      arch = ARCH_X86_64;
      break;
    case EM_386:
      std::cout << "Arch: i386" << std::endl;
      arch = ARCH_X86_32;
      break;
    default:
      std::cout << "could not read arch" << std::endl;
      arch = ARCH_UNDEF;
      break;
    }

    if (elf->pie()) {
      std::cout << "ELF is PIE" << std::endl;
    } else {
      std::cout << "ELF is not PIE" << std::endl;
    }

    regs = new Registers(arch);
    return;
  }
}

Debugger::~Debugger() {
  //delete elf;
  if (regs != NULL) {
    delete regs;
  }

  for (auto& it : elf_table) {
    delete it.second;
  }

  elf_table.clear();
}

void Debugger::reset() { 
  kill(proc, SIGKILL);
  waitpid(proc, &status, 0);

  if (WIFSIGNALED(status)) {
    std::cout << "tracee killed" << std::endl;
  }

  if (elf->pie()) {
    std::cout << "File is PIE" << std::endl;
  } else {
    std::cout << "File is not PIE" << std::endl;
  }


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

    regs->peek(proc);

    for (auto& bp_it : breakpoints) {
      enable_breakpoint(&(bp_it.second));
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


  if (ptrace(PTRACE_GETSIGINFO, proc, NULL, &signal)  == -1) {
    std::cout << "cant decode signal..." << std::endl;
    return -1;
  }

  regs->peek(proc);

  if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
    auto pc = regs->get_pc();

    auto bp_it = breakpoints.find(pc-1);
    if (bp_it != breakpoints.end()) {
      disable_breakpoint(&(bp_it->second));

      regs->set_pc(pc - 1);
      regs->poke(proc);

      single_step()
; 
      enable_breakpoint(&(bp_it->second));
      regs->peek(proc);
    }
    
    std::cout << "stopped at: 0x" << regs->get_pc() << std::endl;
    std::cout << "bp at: 0x" << regs->get_bp() << std::endl;
    std::cout << "sp at: 0x" << regs->get_sp() << std::endl;
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
  //update_regs();
  regs->peek(proc);
}

//////////////////////
// Breakpoint Functions
///////////////////////

void Debugger::set_breakpoint(unsigned long addr) {
  auto bp_it = breakpoints.find(addr);
  if (bp_it != breakpoints.end()) {
    return;
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

  Breakpoint bp = Breakpoint(addr, data);
  enable_breakpoint(&bp);

  breakpoints.emplace(std::pair(addr, bp)); 
}

void Debugger::delete_breakpoint(uint64_t addr) {
  auto bp_it =  breakpoints.find(addr);

  if (bp_it == breakpoints.end()) {
    return;
  }

  disable_breakpoint(&(bp_it->second));

  breakpoints.erase(bp_it); 
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

  for (auto& instr : instructions) {
    instr.set_prefix("   ");

    if (instr.get_addr() == regs->get_pc()) {
      instr.set_prefix(" > ");
    }

    auto bp_it = breakpoints.find(instr.get_addr());
    if (bp_it != breakpoints.end()) {
      instr.set_prefix(" * ");
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
uint64_t Debugger::get_pc() const {
  return regs->get_pc();
}


void Debugger::print_regs()  const {
  std::cout << regs->str() << std::endl;
  
}

void Debugger::print_vmmap() const {
  for (const auto& entry: vmmap) {
    std::cout << entry.str() << std::endl;
  }
}


void Debugger::list_breakpoints()  const{
  switch (arch) {
    case ARCH_X86_64:
    for(auto& bp_it : breakpoints) {
      std::cout << "Breakpoint at 0x" << fmt::addr_64(bp_it.second.get_addr()) << std::endl;
    }
    break;
    case ARCH_X86_32:

    for(auto& bp_it : breakpoints) {
      std::cout << "Breakpoint at 0x" << fmt::addr_32(bp_it.second.get_addr()) << std::endl;
    }
    break;
    default:
    std::cout << "No valid architecture" << std::endl;
    break;
  }
}

void Debugger::print_symbols() const {
  for (auto& entry : elf_table) {
    entry.second->print_symtab();
  }
}

void Debugger::print_sections() const {
  elf->print_sections();
}
