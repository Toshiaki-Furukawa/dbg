#pragma once
#include <vector>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>

#include "dbgtypes.hpp"

struct memory_chunk {
  uint64_t start;
  uint32_t size;
  uint8_t* content;
  //char content[];

} typedef chunk_t;

struct program_state {
  uint64_t addr;
  
  chunk_t heap;
  chunk_t stack; 

  Registers regs;
} typedef state_t;


class ChangeNode {
private:

  std::unordered_map<uint32_t, uint64_t> stack_changes;
  std::unordered_map<uint32_t, uint64_t> heap_changes;
  ChangeNode *parent;
  Registers regs;
  uint64_t addr;
  uint32_t id;

public:
  uint64_t root_heap_start;
  uint32_t root_heap_size;
  uint64_t *root_heap_content; 

  uint64_t root_stack_start;
  uint32_t root_stack_size;
  uint64_t *root_stack_content; 

  ChangeNode* main;
  ChangeNode* branch;

  ChangeNode(state_t&);

  ChangeNode(ChangeNode*);

  ChangeNode(ChangeNode* parent, state_t& state);

  void make_branch(uint32_t);

  void addChild(ChangeNode* child);

  int restore_state(state_t&);

  void set_parent(ChangeNode*);
  void set_branch(ChangeNode*);
  
  void set_main(ChangeNode*);
  
  void set_id(uint32_t);

  uint32_t get_id();

  uint64_t get_addr();

};

class ExecHistory {
private:
  ChangeNode* root_node;
  ChangeNode* current_state;
  uint32_t tree_size;    // used to compute id
  uint32_t branch_numbers;

public:
  ExecHistory();

  void set_root(state_t&);

  void log_goto(state_t&);

  int restore_state_by_id(uint32_t, state_t&);

  void get_path(ChangeNode*, std::vector<uint32_t>&, uint32_t, uint32_t) const;
  
  void subtree_str(ChangeNode*, std::stringstream&, std::string, uint32_t) const;

  std::string str() const;
};
