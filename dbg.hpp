#pragma once
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

#include <cstdint>
#include <map>
#include "elftypes.hpp"
#include "elf.hpp"
#include "dbgtypes.hpp"

class Debugger {
private:
  const char *filename;
  ELF *elf;

  user_regs_struct regs;
  pid_t proc;
  int status;
  siginfo_t signal;

  std::vector<Breakpoint> breakpoints;
  std::vector<MapEntry> vmmap;
  std::map<std::string, ELF*> elf_table;

  architecture arch;

  void enable_breakpoint(Breakpoint *bp);

  void disable_breakpoint(Breakpoint *bp); 

  int update_regs();

  uint64_t get_symbol_addr(std::string sym);

  uint32_t get_symbol_size(std::string sym);

  //  this function is useful to get a estimate of mappings, prior to reading vmmap
  //uint64_t read_vmmap_base();

  void read_vmmap();

  std::string get_file_from_addr(uint64_t addr);
  
  uint8_t *get_bytes_from_file(std::string filename, uint64_t addr, uint32_t n);

  uint8_t *get_bytes_from_memory(uint64_t addr, uint32_t n);


public:
  Debugger (const char *filename);

  ~Debugger();

  void reset();

  int cont();

  void single_step();

  void set_breakpoint(unsigned long addr);

  void delete_breakpoint(uint32_t idx);


  void disassemble(uint64_t addr, size_t n);
  
  void disassemble(std::string symbol); 


  uint8_t *get_bytes(uint64_t adddr, size_t n);

  std::vector<uint64_t> get_long(uint64_t addr, size_t n); 

  std::vector<uint32_t> get_word(uint64_t addr, size_t n);


  void print_regs();

  void print_vmmap();

  void list_breakpoints();

  void print_symbols();

  void print_sections();
};
