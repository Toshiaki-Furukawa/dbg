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
#include "dbgtypes.hpp"
#include "elf.hpp"
#include "elftypes.hpp"
#include "fmt.hpp"
#include "tracer.hpp"

class Debugger {
private:
  std::string filename;
  ELF* elf;
  ELF* libc;

  Registers *regs;
  pid_t proc;
  int status;
  siginfo_t signal;

  std::unordered_map<uint64_t, Breakpoint> breakpoints;
  std::vector<MapEntry> vmmap;
  std::unordered_map<std::string, const ELF*> elf_table;

  ExecHistory program_history;

  arch_t arch;

  void enable_breakpoint(Breakpoint&);

  void disable_breakpoint(Breakpoint&); 

  int update_regs();


  //  this function is useful to get a estimate of mappings, prior to reading vmmap
  //uint64_t read_vmmap_base();

  void read_vmmap();

  std::string get_file_from_addr(uint64_t);

  uint8_t *get_bytes_from_file(std::string, uint64_t, uint32_t);

  uint8_t *get_bytes_from_memory(uint64_t, uint32_t);

  void write_bytes_to_memory(uint64_t, uint8_t*, uint32_t);

  void load_elftable();
  
  void init_proc();


public:
  //Debugger (const char *filename);
  Debugger (std::string filename);

  ~Debugger();

  void run();

  //void reset();

  int cont();

  void single_step();

  void log_state();

  void restore_state(uint32_t);

  void set_breakpoint(unsigned long);

  void delete_breakpoint(uint64_t);


  std::vector<Instruction> disassemble(uint64_t, size_t);

  std::vector<Instruction> disassemble(std::string); 


  uint64_t get_reg(std::string);
  
  uint64_t get_symbol_addr(std::string);

  size_t get_symbol_size(std::string);

  uint8_t *get_bytes(uint64_t, size_t);

  std::vector<uint64_t> get_long(uint64_t, size_t); 

  std::vector<uint32_t> get_word(uint64_t, size_t);


  void print_history() const;

  uint64_t get_pc() const;

  void print_regs() const;

  void print_vmmap() const;

  void list_breakpoints() const;

  void print_symbols() const;

  void print_sections() const;
};
