#include <string>
#include <sstream>
#include <vector>
#include <fstream>
#include <sys/user.h>

#include "elf.hpp"
#include "dbgtypes.hpp"


Registers::Registers(arch_t arch) : arch(arch) { }

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
void Registers::load_x86_64(user_regs_struct *regs) {
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
}

void Registers::load_i386(user_regs_struct *regs) {
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
}


void Registers::load(user_regs_struct *regs) {
  switch (arch) {
    case ARCH_X86_64:
      load_x86_64(regs);
      break;
    case ARCH_X86_32:
      load_i386(regs);
      break;
    default:
      return;
  }
}

uint64_t Registers::get_pc() {
  return pc;
}

std::string Registers::str_x86_64() {
  std::stringstream ss;
  const std::string regs_print_order_x86_64[] = {"rax", "rcx", "rdx", "rsi", "rdi", "rbx", "rbp", "rsp", 
                              "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", 
                              "rip", "eflags", "cs", "ss", "ds", "es", "fs", "gs", "fs_base", "gs_base"};

  for (const auto& r : regs_print_order_x86_64) {
    ss << r << ": 0x" << std::hex << registers[r] << std::endl;
  }
  return ss.str();
}

std::string Registers::str_i386() {
  std::stringstream ss;
  const std::string regs_print_order_i386[] ={ "eax", "ecx", "edx", "esi", "edi", "ebx", "ebp", "esp", 
                              "eip", "eflags", "cs", "ss", "ds", "es", "fs", "gs"}; 

  for (const auto& r : regs_print_order_i386) {
    ss << r << ": 0x" << std::hex << registers[r] << std::endl;
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
  ss << "0x" << std::hex << start_addr << "-0x" << std::hex << end_addr << "   " << permissions_str << "      " 
     << std::hex << size << "  " << std::hex << "   " << offset <<"   "<< file;

  return ss.str();
}
