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
  ELF elf;

  std::vector<Breakpoint> breakpoints;
  user_regs_struct regs;
  pid_t proc;
  int status;
  siginfo_t signal;
  std::vector<MapEntry> vmmap;

  uint64_t base_addr;

  void enable_breakpoint(Breakpoint *bp);

  void disable_breakpoint(Breakpoint *bp); 

  int update_regs();

  //  this function is useful to get a estimate of mappings, prior to reading vmmap
  uint64_t read_vmmap_base();

  void read_vmmap();

public:
  Debugger (const char *filename);

  int cont();

  void reset();

  void print_regs();

  void set_breakpoint(unsigned long addr);

  void delete_breakpoint(uint32_t idx);

  void enable_bp(unsigned int idx); 
      
  void disable_bp(unsigned int idx);

  void disassemble(uint64_t addr, size_t n, disas_mode mode);

  void print_vmmap();

  std::vector<uint64_t> get_long(uint64_t addr, size_t n); 

  std::vector<uint32_t> get_word(uint64_t addr, size_t n);

  uint64_t get_symbol_addr(std::string sym);

  uint32_t get_symbol_size(std::string sym);

  void single_step();

  void list_breakpoints();

  void print_symbols();

  void print_sections();
};
