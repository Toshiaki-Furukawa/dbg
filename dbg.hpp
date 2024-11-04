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
  const ELF* elf;

  //user_regs_struct regs;
  Registers *regs;
  pid_t proc;
  int status;
  siginfo_t signal;

  std::unordered_map<uint64_t, Breakpoint> breakpoints;
  std::vector<MapEntry> vmmap;
  std::unordered_map<std::string, const ELF*> elf_table;

  //History program_history;
  std::vector<Registers> register_log;
  std::vector<std::unordered_map<uint64_t, uint8_t*>> mem_log;

  arch_t arch;

  void enable_breakpoint(Breakpoint*);

  void disable_breakpoint(Breakpoint*); 

  int update_regs();

  uint64_t get_symbol_addr(std::string);

  uint32_t get_symbol_size(std::string);

  //  this function is useful to get a estimate of mappings, prior to reading vmmap
  //uint64_t read_vmmap_base();

  void read_vmmap();

  std::string get_file_from_addr(uint64_t);

  uint8_t *get_bytes_from_file(std::string, uint64_t, uint32_t);

  uint8_t *get_bytes_from_memory(uint64_t, uint32_t);

  void write_bytes_to_memory(uint64_t, uint8_t*, uint32_t);


public:
  Debugger (const char *filename);

  ~Debugger();

  void reset();

  int cont();

  void single_step();

  void log_state();

  void goto_addr(uint64_t);

  void set_breakpoint(unsigned long);

  void delete_breakpoint(uint64_t);


  std::vector<Instruction> disassemble(uint64_t, size_t);

  std::vector<Instruction> disassemble(std::string); 


  uint8_t *get_bytes(uint64_t, size_t);

  std::vector<uint64_t> get_long(uint64_t, size_t); 

  std::vector<uint32_t> get_word(uint64_t, size_t);


  std::vector<Registers>& get_register_history();

  uint64_t get_pc() const;

  void print_regs() const;

  void print_vmmap() const;

  void list_breakpoints() const;

  void print_symbols() const;

  void print_sections() const;
};
