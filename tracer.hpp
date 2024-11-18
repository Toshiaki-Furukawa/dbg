#pragma once
#include <vector>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>

#include "dbgtypes.hpp"

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
  ExecHistory();

  void log(state_t state);

  bool is_logged(uint64_t);

  chunk_t* get_stack(uint32_t);

  chunk_t* get_heap(uint32_t);

  Registers* get_registers(uint32_t);

  std::string str() const;
};
