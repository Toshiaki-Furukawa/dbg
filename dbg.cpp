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
#include <cstring>
#include <map>

#include "elf.hpp"
#include "elftypes.hpp"
#include "dbgtypes.hpp"
#include "dbg.hpp"
#include "disass.hpp"
#include "fmt.hpp"

bool is_elf(std::string file) {
  std::ifstream file_content(file, std::ios::binary | std::ios::ate);

  if (!file_content.is_open()) {
    return false;
  }

  
  char magic[4] = {0x7f, 'E', 'L', 'F'}; 
  file_content.seekg(0, std::ios::beg);
  
  for (const auto& magic_byte : magic) {
    char tmp;
    file_content.get(tmp);
    if (tmp != magic_byte) {
      file_content.close();
      return false;
    }
  }

  file_content.close();
  return true;
}

void Debugger::enable_breakpoint(Breakpoint& bp) {
  if (WIFEXITED(status)) {
    return;
  }

  auto data = ptrace(PTRACE_PEEKDATA, proc, bp.get_addr(), NULL);
  auto mod_data = ((data & ~0xff) | 0xcc);

  ptrace(PTRACE_POKEDATA, proc, bp.get_addr(), mod_data);
  bp.enable();
}

void Debugger::disable_breakpoint(Breakpoint& bp) {
  if (WIFEXITED(status)) {
    return;
  }

  auto data = ptrace(PTRACE_PEEKDATA, proc, bp.get_addr(), NULL);
  auto orig_data = ((data & ~0xff) | bp.get_data());

  ptrace(PTRACE_POKEDATA, proc, bp.get_addr(), orig_data);

  bp.disable(); 
}

uint64_t Debugger::get_symbol_addr(std::string sym) {
  if (elf->get_symbol_addr(sym) != 0) {
    return elf->get_symbol_addr(sym);
  }

  for (const auto& entry : elf_table) {
    auto addr = entry.second->get_symbol_addr(sym);
    if (addr != 0) {
      return addr;
    }
  }
  
  return 0;
}

size_t Debugger::get_symbol_size(std::string sym) {
  if (elf->get_symbol_addr(sym) != 0) {
    return elf->get_symbol_size(sym);
  }

  for (const auto& entry : elf_table) {
    if (entry.second->get_symbol_addr(sym) != 0) {
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
    return ret;
  }
  
  if (entry->get_file() == elf->get_filename()) {
    return entry->get_file(); 
  }

  auto file = elf_table.find(entry->get_file());
  if (file == elf_table.end()) {
    return ret;
  }
  return entry->get_file();
}

uint8_t *Debugger::get_bytes_from_file(std::string filename, uint64_t addr, uint32_t n) {
  if (filename == elf->get_filename()) {
    return elf->get_n_bytes_at_addr(addr, n);
  } else {
    auto file_entry = elf_table.find(filename);

    if (file_entry == elf_table.end()) {
      std::cout << "filename invalid" << std::endl;
      return NULL;
    }
    return file_entry->second->get_n_bytes_at_addr(addr, n);
  } 
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
    std::cout << "could not read from memory" << std::endl;
    delete[] ret;
    return NULL;
  }

  return ret;
}

void Debugger::write_bytes_to_memory(uint64_t addr, uint8_t* bytes, uint32_t n) {
  if (WIFEXITED(status)) {
    std::cout << "Program is no longer beeing run" << std::endl; 
    return;
  }


  struct iovec local_mem[1];
  struct iovec remote_mem[1];

  local_mem[0].iov_base = bytes;
  local_mem[0].iov_len = n;

  remote_mem[0].iov_base = (void *)(addr);
  remote_mem[0].iov_len = n; 

  if (process_vm_writev(proc, local_mem, 1, remote_mem, 1, 0) != n) {
    std::cout << "could not write to memory" << std::endl;
  }
}


//Debugger::Debugger (const char *filename) : filename(filename) {
Debugger::Debugger (std::string filename) : filename(filename) {
  if (!std::filesystem::exists(filename)) {
    std::cout << "file does not exist" << std::endl;
    return;
  }

  elf = new ELF(std::filesystem::absolute(filename));
  elf_table = {};

  arch = elf->get_machine();

  if (elf->pie()) {
    std::cout << "ELF is PIE" << std::endl;
  } else {
    std::cout << "ELF is not PIE" << std::endl;
  }

  libc = NULL;  
  regs = new Registers(arch);
  init_proc();

  read_vmmap();

  regs->peek(proc);
  kill(proc, SIGKILL);
  waitpid(proc, &status, 0);
  proc = 0;
  return;
}

Debugger::~Debugger() {
  if (regs != NULL) {
    delete regs;
  }

  for (auto& it : elf_table) {
    delete it.second;
  }

  elf_table.clear();
}


void Debugger::load_elftable() {
  for (const auto& entry: vmmap) {
    auto elf_filename = entry.get_file();

    if (is_elf(elf_filename) && (elf_table.find(elf_filename) == elf_table.end())) {
      ELF *vmmap_elf_file = new ELF(elf_filename.c_str());
      vmmap_elf_file->rebase(entry.get_start());

      elf_table.insert(std::pair(elf_filename, vmmap_elf_file));
    }
  }
}

void Debugger::init_proc() {
  proc = fork();
  if (proc == -1) {
    std::cout << "Error while forking new process" << std::endl;
    exit(-1);
  }

  if (proc == 0) {
    personality(ADDR_NO_RANDOMIZE);

    ptrace(PTRACE_TRACEME, proc, NULL, NULL);

    execl(filename.c_str(), filename.c_str(), NULL, NULL);
  } 
    waitpid(proc, &status, 0);
    ptrace(PTRACE_SETOPTIONS, proc, NULL, PTRACE_O_EXITKILL);

    read_vmmap();
    //load_elftable();

    // get libc

    for (const auto& entry: vmmap)  {
      auto filename = entry.get_file();

      if (entry.get_file() == elf->get_filename()) {
        elf->rebase(entry.get_start());
        break;
      }
    }

    // inject shellcode
    auto start_addr = elf->get_symbol_addr("_start");

    uint64_t shellcode;
    if (arch == arch_t::ARCH_X86_64) {
      shellcode = 0x90ccd0ff57909090;
    } else if (arch == arch_t::ARCH_X86_32) {
      shellcode = 0x90ccd0ff90909090;
    } else {
      std::cout << "[ERROR] architecture not valid" << std::endl;
      return;
    }

    uint64_t orig_start = ptrace(PTRACE_PEEKDATA, proc,start_addr, NULL);

    if (ptrace(PTRACE_POKEDATA, proc, start_addr, shellcode) < 0) {
      std::cout << "Could not inject shellcode" << std::endl;
      return;
    }


    // Stop at _start for process injection 
    char data = '\x90'; //static_cast<char>(bytes[0]);

    Breakpoint start_bp = Breakpoint(start_addr, data);
    enable_breakpoint(start_bp);
  

    // continue to _start 
    ptrace(PTRACE_CONT, proc, NULL, NULL);
    waitpid(proc, &status, 0);

    regs->peek(proc);

    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
      auto pc = regs->get_pc();
      
      // restore exectution
      if (pc-1 == start_addr) {
        disable_breakpoint(start_bp);

        regs->set_pc(pc - 1);
        regs->poke(proc);

        single_step(); 

        regs->peek(proc);
      }
    }
    
    read_vmmap();

    // setup libc
    if (libc == NULL) {
      for (const auto& entry: vmmap) {
        auto filename = entry.get_file();

        if (filename.find("libc") != std::string::npos) {
          libc = new ELF(filename);
          libc->rebase(entry.get_start());
          break;
        }
      }
    }

    uint64_t malloc_addr = libc->get_symbol_addr("malloc");

    // registers that will be changed
    uint64_t orig_sp;
    uint64_t orig_di;
    uint64_t orig_ax;

    std::string di;
    std::string sp; 
    std::string ax;

    // setup registers for call
    if (arch == arch_t::ARCH_X86_64) {
      orig_sp = regs->get_by_name("rsp");
      orig_di = regs->get_by_name("rdi");
      orig_ax = regs->get_by_name("rax");

      di = "rdi";
      ax = "rax";
      sp = "rsp";
    } else if (arch == arch_t::ARCH_X86_32) {
      orig_sp = regs->get_by_name("esp");
      orig_di = regs->get_by_name("edi");
      orig_ax = regs->get_by_name("eax");

      di = "edi";
      ax = "eax";
      sp = "esp";
    } else {
      std::cout << "[ERROR] architecture not valid" << std::endl;
      return;
    }
    //auto orig_esp = regs->get_by_name("esp");
    //auto orig_ebx = regs->get_by_name("ebx");
    //auto orig_eax = regs->get_by_name("eax");

    //regs->set_by_name("ebx", 0x1);
    regs->set_by_name(di, 0x1);
    regs->set_by_name(ax, malloc_addr);
    //regs->set_by_name("eax", malloc_addr);
    regs->poke(proc);

    ptrace(PTRACE_CONT, proc, NULL, NULL);

    waitpid(proc, &status, 0);

    if (WIFSTOPPED(status)) {
      if (ptrace(PTRACE_POKEDATA, proc, start_addr, orig_start) < 0) {
        std::cout << "could not restore state" << std::endl;
      }

      regs->set_pc(start_addr);

      //regs->set_by_name("ebx", orig_ebx);
      //regs->set_by_name("esp", orig_esp);
      //regs->set_by_name("eax", orig_eax);
      regs->set_by_name(di, orig_di);
      regs->set_by_name(sp, orig_sp);
      regs->set_by_name(ax, orig_ax);
      regs->poke(proc);
    } else {
      std::cout << "shellcode injection failed" << std::endl;
    }

    return;
}

void Debugger::run() {
  if (proc != 0) {
    kill(proc, SIGKILL);
    waitpid(proc, &status, 0);
  }

  if (WIFSIGNALED(status)) {
    std::cout << "tracee killed" << std::endl;
  }


  init_proc();
  //load_elftable();

  for (auto& bp: breakpoints) {
    enable_breakpoint(bp.second);
  } 

  cont();
}

int Debugger::cont() {
  if (WIFEXITED(status) || proc == 0) {
    std::cout << "program no longer being run" << std::endl;
    return 0;
  }

  // step over breakpoint if we are at  correct posiiton
  regs->peek(proc);
  if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
    auto pc = regs->get_pc();

    auto bp_it = breakpoints.find(pc);
    if (bp_it != breakpoints.end()) {
      single_step();
    }
  }

  regs->peek(proc);

  for (auto& bp_it : breakpoints) {
    enable_breakpoint(bp_it.second);
  }

  ptrace(PTRACE_CONT, proc, NULL, NULL);

  waitpid(proc, &status, 0);
  if (WIFEXITED(status)) { 
    return 0;
  }

  read_vmmap();    
  load_elftable();

  if (ptrace(PTRACE_GETSIGINFO, proc, NULL, &signal)  == -1) {
    std::cout << "cant decode signal..." << std::endl;
    return -1;
  }

  // disable breakpoint
  if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
    regs->peek(proc);
    auto pc = regs->get_pc();

    auto bp_it = breakpoints.find(pc-1);
    if (bp_it != breakpoints.end()) {
      disable_breakpoint(bp_it->second);

      regs->set_pc(pc-1);
      regs->poke(proc);
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
  if (proc == 0 || WIFEXITED(status)) {
    return;
  }

  // TODO
  regs->peek(proc);

  // skip breakpoint if set at current position
  auto bp_it = breakpoints.find(regs->get_pc());
  if (bp_it != breakpoints.end()) {
    disable_breakpoint(bp_it->second);
  }

  if (ptrace(PTRACE_SINGLESTEP, proc, NULL, NULL)) {
    std::cout << "single step failed" << std::endl;
    return;
  }

  waitpid(proc, &status, 0);
  if (bp_it != breakpoints.end()) {
    enable_breakpoint(bp_it->second);
  }

  regs->peek(proc);

}

void Debugger::log_state() {
  if (proc == 0 || WIFEXITED(status)) {
    return;
  }

  state_t state = {regs->get_pc(), {0x0, 0x0, 0x0}, {0x0, 0x0, 0x0}, *regs};

  for (const auto& vmmap_entry : vmmap ) {
    if (vmmap_entry.get_file() == "[heap]") {
      std::cout << "found heap" << std::endl;
      state.heap.start = vmmap_entry.get_start();
      state.heap.size = vmmap_entry.get_size();

      state.heap.content = get_bytes_from_memory(state.heap.start, state.heap.size);
    } else if (vmmap_entry.get_file() == "[stack]") {
      std::cout << "found stack" << std::endl;
      state.stack.start = vmmap_entry.get_start();
      state.stack.size = vmmap_entry.get_size();

      state.stack.content = get_bytes_from_memory(state.stack.start, state.stack.size);
    }
  }

  program_history.log(state);
}

void Debugger::restore_state(uint32_t n) {
  if (proc == 0 || WIFEXITED(status)) {
    init_proc();
  } else {
    kill(proc, SIGKILL);
    waitpid(proc, &status, 0);
   
    init_proc(); 
  }

  auto state_regs = program_history.get_registers(n);

  if (state_regs == nullptr) {
    std::cout << "could not find state" << std::endl;
    return;
  }

  state_regs->poke(proc);

  auto heap = program_history.get_heap(n);
  if (heap == nullptr) {
    std::cout << "[Warning] No heap info stored" << std::endl;
  }

  auto stack = program_history.get_stack(n);
  if (stack == nullptr) {
    std::cout << "[Warning] No stack info stored" << std::endl;
  }
 
  for (const auto& vmmap_entry : vmmap) {
    if (vmmap_entry.get_file() == "[heap]" && heap != nullptr) {
      write_bytes_to_memory(heap->start, heap->content, heap->size);
    } else if (vmmap_entry.get_file() == "[stack]" && heap != nullptr) {
      write_bytes_to_memory(stack->start, stack->content, stack->size);
    }
  }

  // restore breakpoints 
  regs->peek(proc);
  for (auto& bp: breakpoints) {
    if (regs->get_pc() != bp.first) {
      enable_breakpoint(bp.second);
    }
  }
 
  std::cout << "successfully restored state" << std::endl;
  return;
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
  enable_breakpoint(bp);

  breakpoints.emplace(std::pair(addr, bp)); 
}

void Debugger::delete_breakpoint(uint64_t addr) {
  auto bp_it =  breakpoints.find(addr);

  if (bp_it == breakpoints.end()) {
    return;
  }

  disable_breakpoint(bp_it->second);

  breakpoints.erase(bp_it); 
}

////////////////////
// DISASSEMBLE
////////////////////

std::vector<Instruction> Debugger::disassemble(uint64_t addr, size_t n) { //disas_mode mode) {
  if (n == 0) {
    return {};
  }
 
  std::vector<Instruction> instructions;
  std::string filename = elf->get_filename();

  if (!vmmap.empty()) {
    filename = get_file_from_addr(addr);
  }

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

    auto bp_it = breakpoints.find(instr.get_addr());
    if (bp_it != breakpoints.end()) {
      instr.set_prefix(" * ");
    }

    if (instr.get_addr() == regs->get_pc() && (!WIFEXITED(status) || proc == 0)) {
      instr.set_prefix(" > ");
    }

  } 

  return instructions;
}

std::vector<Instruction> Debugger::disassemble(std::string symbol) {
  std::vector<Instruction> instructions;
  
  uint64_t addr = get_symbol_addr(symbol);
  uint32_t size = get_symbol_size(symbol);

  if (addr == 0) {
    std::cout << "Symbol not found" << std::endl;
    return instructions;
  }

  instructions = disassemble(addr, size);
  return instructions;
}

/////////////////////
// READM FROM MEMORY
////////////////////

uint64_t Debugger::get_reg(std::string reg) {
  if (proc == 0 || WIFEXITED(status)) {
    return 0;
  }

  return regs->get_by_name(reg);
}

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
void Debugger::print_history() const {
  std::cout << program_history.str() << std::endl;
}

uint64_t Debugger::get_pc() const {
  if (proc == 0 || WIFEXITED(status)) {
    return 0;
  }
  return regs->get_pc();
}


void Debugger::print_regs()  const {
  if (proc == 0 || WIFEXITED(status)) {
    return;
  }

  std::cout << regs->str() << std::endl;
  
}

void Debugger::print_vmmap() const {
  if (proc == 0 || WIFEXITED(status)) {
    return;
  }

  for (const auto& entry: vmmap) {
    std::cout << entry.str(arch) << std::endl;
  }
}


void Debugger::list_breakpoints()  const{
  switch (arch) {
    case ARCH_X86_64:
    for(auto& bp_it : breakpoints) {
      std::cout << "Breakpoint set at " << fmt::yellow << fmt::addr_64(bp_it.second.get_addr()) << fmt::endc << std::endl;
    }
    break;
    case ARCH_X86_32:

    for(auto& bp_it : breakpoints) {
      std::cout << "Breakpoint set at " << fmt::yellow << fmt::addr_32(bp_it.second.get_addr()) << fmt::endc << std::endl;
    }
    break;
    default:
    std::cout << "No valid architecture" << std::endl;
    break;
  }
}

void Debugger::print_symbols() const {
  for (auto& entry : elf_table) {
    std::cout << "HELLO" << std::endl;
    if (entry.second->get_filename() != elf->get_filename()) {
      entry.second->print_symtab();
    }
  }

  elf->print_symtab();
}

void Debugger::print_sections() const {
  elf->print_sections();
}
