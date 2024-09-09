#pragma once
#include <vector>
#include <cstdint>
#include <string>
#include <sstream>
#include <iostream>
#include <sys/user.h>
#include "elf.hpp"

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

  std::map<std::string, uint64_t> registers;

  arch_t arch;

  void load_x86_64(user_regs_struct *regs);

public:
  Registers(arch_t arch);
    
  void load(user_regs_struct *regs);

  uint64_t get_pc();

  std::string str();

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

  uint64_t get_start();

  uint64_t get_end();

  uint32_t get_size();

  uint32_t get_offset();

  std::string get_file();

  bool contains(uint64_t addr);

  std::string str(); 
};
