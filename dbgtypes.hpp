#pragma once
#include <vector>
#include <cstdint>
#include <string>
#include <sstream>
#include <iostream>
#include "elf.hpp"

enum disas_mode {
  DISAS_MODE_WORD,
  DISAS_MODE_BYTE
};

enum architecture {
  ARCH_X86_64,
  ARCH_X86_32,  
  ARCH_UNDEF, 
};

struct command {
  std::string cmd;
  std::vector<std::string> args;
} typedef command_t;

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
