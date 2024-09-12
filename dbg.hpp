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
#include <unordered_map>
#include "elftypes.hpp"
#include "elf.hpp"
#include "dbgtypes.hpp"

class Debugger {
private:
  const char *filename;
  ELF *elf;

  //user_regs_struct regs;
  Registers *regs;
  pid_t proc;
  int status;
  siginfo_t signal;

  std::unordered_map<uint64_t, Breakpoint> breakpoints;
  std::vector<MapEntry> vmmap;
  std::unordered_map<std::string, ELF*> elf_table;

  arch_t arch;

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

  void delete_breakpoint(uint64_t addr);


  std::vector<Instruction> disassemble(uint64_t addr, size_t n);

  std::vector<Instruction> disassemble(std::string symbol); 


  uint8_t *get_bytes(uint64_t adddr, size_t n);

  std::vector<uint64_t> get_long(uint64_t addr, size_t n); 

  std::vector<uint32_t> get_word(uint64_t addr, size_t n);

  uint64_t get_pc() const;

  void print_regs() const;

  void print_vmmap() const;

  void list_breakpoints() const;

  void print_symbols() const;

  void print_sections() const;
};
