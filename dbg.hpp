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


struct memory_chunk {
  uint64_t start;
  uint32_t size;
  uint8_t* content;

} typedef chunk_t;

struct program_state {
  uint64_t addr;
  
  chunk_t heap;
  chunk_t stack; 

  Registers regs;
} typedef state_t;

class ExecHistory {
private:
  std::vector<state_t> state_log;

public:
  ExecHistory() {
    state_log = {};
  }

  void log(state_t state) {
    state_log.emplace_back(state); 
  }

  bool is_logged(uint64_t addr) {
    for (const auto& state : state_log) {
      if (state.addr == addr) {
        return true;
      }
    }

    return false;
  }

  chunk_t* get_stack(uint32_t n) {
    if (n >= state_log.size()) {
      return nullptr;
    }

    if (state_log[n].stack.start == 0x0) {
      return nullptr;
    }
    return &(state_log[n].stack);
  }

  chunk_t* get_heap(uint32_t n) {
    if (n >= state_log.size()) {
      return nullptr;
    }

    if (state_log[n].heap.start == 0x0) {
      return nullptr;
    }
    return &(state_log[n].heap);
  }

  Registers* get_registers(uint32_t n) {
    std::cout << "HI" << std::endl;
    if (n >= state_log.size()) {
      std::cout << "HI2" << std::endl;
      return nullptr;
    }

    return &(state_log[n].regs);
  }

  std::string str() const {
    std::stringstream ss;
    int idx = 0;
    for (const auto& state : state_log) {
      ss << "Checkpoint nr. " << idx << " at PC: " << fmt::addr_64(state.addr) <<  std::endl;
      ss << "   heap: " << fmt::addr_64(state.heap.start) << std::endl;
      ss << "   stack: " << fmt::addr_64(state.stack.start) << std::endl << std::endl;
    } 
    return ss.str();   
  }
};

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
