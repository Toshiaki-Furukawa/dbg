#include <string>
#include <sstream>
#include <vector>
#include <fstream>
#include <sys/user.h>

#include "elf.hpp"
#include "dbgtypes.hpp"


Registers::Registers(arch_t arch) : arch(arch) {}

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
  registers["rip"] = regs->rip;
}

void Registers::load(user_regs_struct *regs) {
  load_x86_64(regs);
}

uint64_t Registers::get_pc() {
  return pc;
}

std::string Registers::str() {
  std::stringstream ss;

  for (auto& kv : registers) {
    ss << kv.first << ": 0x" << std::hex << kv.second << std::endl;
  }
  return ss.str();
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
