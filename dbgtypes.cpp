#include <string>
#include <sstream>
#include <vector>
#include <fstream>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <iomanip>

#include "elf.hpp"
#include "dbgtypes.hpp"
#include "fmt.hpp"


Registers::Registers(arch_t arch) : arch(arch)  { }

/* regs struct

struct user_regs_struct
{
  unsigned long r15;
  unsigned long r14;
  unsigned long r13;
  unsigned long r12;
  unsigned long rbp;
  unsigned long rbx;
  unsigned long r11;
  unsigned long r10;
  unsigned long r9;
  unsigned long r8;
  unsigned long rax;
  unsigned long rcx;
  unsigned long rdx;
  unsigned long rsi;
  unsigned long rdi;
  unsigned long orig_rax;
  unsigned long rip;
  unsigned long cs;
  unsigned long eflags;
  unsigned long rsp;
  unsigned long ss;
  unsigned long fs_base;
  unsigned long gs_base;
  unsigned long ds;
  unsigned long es;
  unsigned long fs;
  unsigned long gs;
};


*/
void Registers::unpack_x86_64(user_regs_struct *regs) {
  pc = regs->rip;
  bp = regs->rbp;
  sp = regs->rsp; 

  registers["rax"] = regs->rax;
  registers["rcx"] = regs->rcx;
  registers["rdx"] = regs->rdx;
  registers["rsi"] = regs->rsi;
  registers["rdi"] = regs->rdi;
  registers["rbx"] = regs->rbx;
  registers["rbp"] = regs->rbp;
  registers["rsp"] = regs->rsp;

  registers["r8"] = regs->r8;
  registers["r9"] = regs->r9;
  registers["r10"] = regs->r10;
  registers["r11"] = regs->r11;
  registers["r12"] = regs->r12;
  registers["r13"] = regs->r13;
  registers["r14"] = regs->r14;
  registers["r15"] = regs->r15;

  registers["rip"] = regs->rip;

  registers["eflags"] = regs->eflags;

  registers["cs"] = regs->cs;
  registers["ss"] = regs->ss;
  registers["ds"] = regs->ds;
  registers["es"] = regs->es;
  registers["fs"] = regs->fs;
  registers["gs"] = regs->gs;

  registers["fs_base"] = regs->fs_base;
  registers["gs_base"] = regs->gs_base;
  registers["orig_rax"] = regs->orig_rax;
}

struct user_regs_struct Registers::pack_x86_64() {
  struct user_regs_struct ureg_struct;


  ureg_struct.rax = registers["rax"];
  ureg_struct.rcx = registers["rcx"];
  ureg_struct.rdx = registers["rdx"];
  ureg_struct.rsi = registers["rsi"];
  ureg_struct.rdx = registers["rdx"];
  ureg_struct.rbx = registers["rbx"];
  ureg_struct.rbp = registers["rbp"];
  ureg_struct.rsp = registers["rsp"];

  ureg_struct.r8 = registers["r8"];
  ureg_struct.r9 = registers["r9"];
  ureg_struct.r10 = registers["r10"];
  ureg_struct.r11 = registers["r11"];
  ureg_struct.r12 = registers["r12"];
  ureg_struct.r13 = registers["r13"];
  ureg_struct.r14 = registers["r14"];
  ureg_struct.r15 = registers["r15"];

  ureg_struct.rip = registers["rip"];

  ureg_struct.eflags = registers["eflags"];

  ureg_struct.cs = registers["cs"];
  ureg_struct.ss = registers["ss"];
  ureg_struct.ds = registers["ds"];
  ureg_struct.es = registers["es"];
  ureg_struct.fs = registers["fs"];
  ureg_struct.gs = registers["gs"];

  ureg_struct.fs_base = registers["fs_base"];
  ureg_struct.gs_base = registers["gs_base"];
  ureg_struct.orig_rax = registers["orig_rax"];

  return ureg_struct;
}

void Registers::unpack_i386(user_regs_struct *regs) {
  pc = regs->rip;
  bp = regs->rbp;
  sp = regs->rsp; 

  registers["eax"] = regs->rax;
  registers["ecx"] = regs->rcx;
  registers["edx"] = regs->rdx;
  registers["esi"] = regs->rsi;
  registers["edi"] = regs->rdi;
  registers["ebx"] = regs->rbx;
  registers["ebp"] = regs->rbp;
  registers["esp"] = regs->rsp;

  registers["eip"] = regs->rip;

  registers["eflags"] = regs->eflags;

  registers["cs"] = regs->cs;
  registers["ss"] = regs->ss;
  registers["ds"] = regs->ds;
  registers["es"] = regs->es;
  registers["fs"] = regs->fs;
  registers["gs"] = regs->gs;
  registers["orig_eax"] = regs->orig_rax;


  // not part of i386 but we need them
  registers["r8"] = regs->r8;
  registers["r9"] = regs->r9;
  registers["r10"] = regs->r10;
  registers["r11"] = regs->r11;
  registers["r12"] = regs->r12;
  registers["r13"] = regs->r13;
  registers["r14"] = regs->r14;
  registers["r15"] = regs->r15;
  registers["fs_base"] = regs->fs_base;
  registers["gs_base"] = regs->gs_base;

}

struct user_regs_struct Registers::pack_i386() {
  struct user_regs_struct ureg_struct;


  ureg_struct.rax = registers["eax"];
  ureg_struct.rcx = registers["ecx"];
  ureg_struct.rdx = registers["edx"];
  ureg_struct.rsi = registers["esi"];
  ureg_struct.rdx = registers["edx"];
  ureg_struct.rbx = registers["ebx"];
  ureg_struct.rbp = registers["ebp"];
  ureg_struct.rsp = registers["esp"];


  ureg_struct.rip = registers["eip"];

  ureg_struct.eflags = registers["eflags"];
  ureg_struct.orig_rax = registers["orig_eax"];

  ureg_struct.cs = registers["cs"];
  ureg_struct.ss = registers["ss"];
  ureg_struct.ds = registers["ds"];
  ureg_struct.es = registers["es"];
  ureg_struct.fs = registers["fs"];
  ureg_struct.gs = registers["gs"];

  // NOT actually part of 32 bit registers but we need them or everything breaks
  ureg_struct.fs_base = registers["fs_base"];
  ureg_struct.gs_base = registers["gs_base"];
  ureg_struct.r8 = registers["r8"];
  ureg_struct.r9 = registers["r9"];
  ureg_struct.r10 = registers["r10"];
  ureg_struct.r11 = registers["r11"];
  ureg_struct.r12 = registers["r12"];
  ureg_struct.r13 = registers["r13"];
  ureg_struct.r14 = registers["r14"];
  ureg_struct.r15 = registers["r15"];

  return ureg_struct;
}

void Registers::peek(pid_t pid) {
  user_regs_struct ureg_struct;
  if (ptrace(PTRACE_GETREGS, pid, NULL, &ureg_struct) == -1) {
    std::cout << "Error: ptrace failed to get registers" << std::endl;
  }

  switch (arch) {
    case ARCH_X86_64:
      unpack_x86_64(&ureg_struct);
      break;
    case ARCH_X86_32:
      unpack_i386(&ureg_struct);
      break;
    default:
      return;
  }
}

void Registers::poke(pid_t pid) {
  user_regs_struct ureg_struct;

  switch (arch) {
    case ARCH_X86_64:
      ureg_struct = pack_x86_64();
      break;
    case ARCH_X86_32:
      ureg_struct = pack_i386();
      break;
    default:
      return;
  }

  //std::cout << "pc now: " << std::hex << ureg_struct.rip << std::endl;

  if (ptrace(PTRACE_SETREGS, pid, NULL, &ureg_struct) == -1) {
    std::cout << "could not write registers" << std::endl;
  }
}


uint64_t Registers::get_pc() {
  return pc;
}

uint64_t Registers::get_sp() {
  return sp;
}

uint64_t Registers::get_bp() {
  return bp;
}

uint64_t Registers::get_by_name(std::string name) {
  auto it = registers.find(name);
  if (it == registers.end()) {
    return 0;
  }
  return it->second;
}

void Registers::set_pc(uint64_t value) {
  pc = value;
  switch (arch) {
    case ARCH_X86_64:
      registers["rip"] = value;
      break;
    case ARCH_X86_32:
      registers["eip"] = value;
      break;
    default:
      return;
  }
}

void Registers::set_bp(uint64_t value) {
  bp = value;
  switch (arch) {
    case ARCH_X86_64:
      registers["rbp"] = value;
      break;
    case ARCH_X86_32:
      registers["ebp"] = value;
      break;
    default:
      return;
  }
}

void Registers::set_sp(uint64_t value) {
  sp = value;
  switch (arch) {
    case ARCH_X86_64:
      registers["rsp"] = value;
      break;
    case ARCH_X86_32:
      registers["esp"] = value;
      break;
    default:
      return;
  }
}

void Registers::set_by_name(std::string name, uint64_t value) {
  auto it = registers.find(name);
  if (it == registers.end()) {
    return;
  }

  it->second = value;
}



std::string Registers::str_x86_64() {
  std::stringstream ss;
  const std::string regs_print_order_x86_64[] = {"rax", "rcx", "rdx", "rsi", "rdi", "rbx", "rbp", "rsp", 
                              "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", 
                              "rip", "eflags", "cs", "ss", "ds", "es", "fs", "gs", "fs_base", "gs_base"};

  for (const auto& r : regs_print_order_x86_64) {
    //ss << r << ": 0x" << std::hex << registers[r] << std::endl;
    ss << fmt::fleft(8) << r << fmt::addr_64(registers[r]) << std::endl;
  }
  return ss.str();
}

std::string Registers::str_i386() {
  std::stringstream ss;
  const std::string regs_print_order_i386[] ={ "eax", "ecx", "edx", "esi", "edi", "ebx", "ebp", "esp", 
                              "eip", "eflags", "cs", "ss", "ds", "es", "fs", "gs"}; 

  for (const auto& r : regs_print_order_i386) {
    ss << fmt::fleft(8) <<  r << fmt::addr_32(registers[r]) << std::endl;
  }
  return ss.str();
}


std::string Registers::str() {
  switch (arch) {
    case ARCH_X86_64:
      return str_x86_64();
    case ARCH_X86_32:
      return str_i386();
    default:
      return "Architecture not recognized";
  }
}


Breakpoint::Breakpoint(uint64_t bp_addr, uint8_t orig_data) 
  : addr(bp_addr), data(orig_data), active(true) {}
  
uint64_t Breakpoint::get_addr() const {
  return addr;
} 
  
uint64_t Breakpoint::get_data() const {
  return data;
}

uint64_t Breakpoint::get_mod_data() const {
  unsigned long new_data = ((data & ~0xff) | 0xcc);
  return new_data;
}

void Breakpoint::enable() {
  active = true;
}

void Breakpoint::disable() {
  active = false;
}

MapEntry::MapEntry(std::string entry_str) {
  start_addr = 0;
  end_addr = 0;

  std::string start_addr_str;
  std::string end_addr_str;
  std::string offset_str;

  std::stringstream entry(entry_str);

  std::getline(entry, start_addr_str, '-');
  std::getline(entry, end_addr_str, ' ');
  std::getline(entry, permissions_str, ' ');
  std::getline(entry, offset_str, ' ');

  while (getline(entry, file, ' '));

  if (start_addr_str.size() > 8*2 || end_addr_str.size() > 8*2 || offset_str.size() > 8*2) {
    return;
  }
     
  start_addr = std::stoul(start_addr_str, NULL, 16); 
  end_addr = std::stoul(end_addr_str, NULL, 16); 

  offset = std::stoul(offset_str, NULL, 16);
  if (permissions_str.size() != 4) {
    std::cout << "could not get permissions" << std::endl;
    return;
  }

  for (int i = 0; i < 4; i++) {
    if(permissions_str[i] != '-') {
      permissions[i] = true;
    } else {
      permissions[i] = false;
    }
  }

  size = end_addr - start_addr;
}

uint64_t MapEntry::get_start() {
  return start_addr;
}

uint64_t MapEntry::get_end() {
  return end_addr;
}

uint32_t MapEntry::get_size() {
  return size;
}

uint32_t MapEntry::get_offset() {
  return offset;
}

std::string MapEntry::get_file() {
  return file;
}

bool MapEntry::contains(uint64_t addr) {
  if (addr >= start_addr && addr < end_addr) {
    return true;
  }
    return false;
}

std::string MapEntry::str() {
  std::stringstream ss;
  //ss << "0x" << std::hex << start_addr << "-0x" << std::hex << end_addr << "   " << permissions_str << "      " 
  //   << std::hex << size << "  " << std::hex << "   " << offset <<"   "<< file;

  ss << fmt::addr_64(start_addr) << "-" << fmt::addr_64(end_addr) << " " << permissions_str 
     << "  " << fmt::fleft(7) << std::hex << size  << " " << fmt::fleft(7) << std::hex << offset << file;
  return ss.str();
}
