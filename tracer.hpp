#pragma once
#include <vector>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>
#include <memory>

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

struct change {
  std::shared_ptr<state_t> state;
  std::vector<change*> children;
  uint32_t id;
} typedef cnode_t;

class ExecHistory {
private:
  cnode_t ctree_root;
  cnode_t* current_state;

public:
  ExecHistory();

  void set_root(state_t&);

  void log(state_t&);

  void log_goto(state_t&);

  state_t* get_state_by_id(uint32_t);

  std::string str() const;
};
