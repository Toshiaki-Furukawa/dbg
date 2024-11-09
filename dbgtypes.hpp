#pragma once
#include <vector>
#include <cstdint>
#include <string>
#include <sstream>
#include <iostream>
#include <sys/user.h>
#include <unordered_map>

//#include "elf.hpp"

enum disas_mode {
  DISAS_MODE_WORD,
  DISAS_MODE_BYTE
};

enum arch_t {
  ARCH_X86_64,
  ARCH_X86_32,  
  ARCH_UNDEF, 
};

struct command {
  std::string cmd;
  std::vector<std::string> args;
} typedef command_t;

class Registers {
private: 
  uint64_t pc;
  uint64_t bp;
  uint64_t sp;

  std::unordered_map<std::string, uint64_t> registers;

  arch_t arch;

  //std::string regs_print_order_x86_64[];

  void unpack_x86_64(user_regs_struct *regs);
  struct user_regs_struct pack_x86_64();

  void unpack_i386(user_regs_struct *regs);
  struct user_regs_struct pack_i386();

public:
  Registers(arch_t arch);

  void reset_proc(pid_t pid);
    
  void peek(pid_t pid);

  void poke(pid_t proc_pid);

  uint64_t get_pc() const;
  
  uint64_t get_sp() const;

  uint64_t get_bp() const;
  
  uint64_t get_by_name(std::string name) const;

  void set_by_name(std::string name, uint64_t value);

  void set_pc(uint64_t value);

  void set_sp(uint64_t value);

  void set_bp(uint64_t value);
  
  std::string str_x86_64() const;

  std::string str_i386() const;

  std::string str() const;

};

class Breakpoint {
private:
    uint64_t addr;
    uint8_t data;
    bool active; 

public:
  Breakpoint(uint64_t bp_addr, uint8_t orig_data);
  
  uint64_t get_addr() const;
  
  uint64_t get_data() const;

  uint64_t get_mod_data() const; 

  void enable();

  void disable();
};


class MapEntry {
private:
  uint64_t start_addr; 
  uint64_t end_addr; 
  bool permissions[4]; // R W X P
  uint32_t size;
  uint32_t offset;
  std::string file;
  std::string permissions_str;

public:
  MapEntry(std::string entry_str);

  uint64_t get_start() const;

  uint64_t get_end() const;

  uint32_t get_size() const;

  uint32_t get_offset() const;

  bool is_writable() const;

  std::string get_file() const;

  bool contains(uint64_t addr) const;

  std::string str(arch_t) const;  
};
