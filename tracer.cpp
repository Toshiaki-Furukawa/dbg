#include <vector>
#include <string>
#include <sstream>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <deque>
#include <unordered_map>

#include "dbgtypes.hpp"
#include "tracer.hpp"
#include "fmt.hpp"

ChangeNode::ChangeNode(state_t& state) {
  chunk_t stack = state.stack;
  chunk_t heap = state.heap;
 
  id = 0;
  addr = state.addr;

  root_heap_start = heap.start;
  root_heap_size = heap.size;
  root_heap_content = new uint64_t[heap.size/sizeof(uint64_t)];

  std::memcpy(root_heap_content, heap.content, heap.size/sizeof(uint64_t));

  root_stack_start = stack.start;
  root_stack_size = stack.size;
  root_stack_content = new uint64_t[stack.size/sizeof(uint64_t)];

  std::memcpy(root_stack_content, stack.content, stack.size/sizeof(uint64_t));

  stack_changes = {};
  heap_changes = {};
  parent = nullptr;
  children = {};

  regs = state.regs;
}

ChangeNode::ChangeNode(ChangeNode* parent, state_t& state) {
  chunk_t stack = state.stack;
  chunk_t heap = state.heap;
 
  this->parent = parent;
  root_heap_size = parent->root_heap_size;
  root_heap_start = parent->root_heap_start;
  root_heap_content = parent->root_heap_content;

  root_stack_size = parent->root_stack_size;
  root_stack_start = parent->root_stack_start;
  root_stack_content = parent->root_stack_content;

  id = parent->get_id() + 1;
  regs = state.regs;
  addr = state.addr;
  children = {};
  stack_changes = {};
  heap_changes = {};

  if (root_heap_size != heap.size) {
    std::cout << "[Warning] Heap sizes do not match" << std::endl;
  }
  if (root_stack_size != stack.size) {
    std::cout << "[Warning] Stack sizes do not match" << std::endl;
  }

  size_t heap_words_size =(heap.size / sizeof(uint64_t))*sizeof(uint64_t);
  size_t stack_words_size =(stack.size / sizeof(uint64_t))*sizeof(uint64_t); 
  uint64_t heap_words[heap.size/sizeof(uint64_t)];
  uint64_t stack_words[stack.size/sizeof(uint64_t)];

  std::memcpy(heap_words, heap.content, heap_words_size);
  std::memcpy(stack_words, stack.content, stack_words_size);

  for (size_t i = 0; i < heap.size/sizeof(uint64_t); i++) {
    heap_changes[i] = heap_words[i];
  }

  for (size_t i = 0; i < heap.size/sizeof(uint64_t); i++) {
    stack_changes[i] = stack_words[i];
  }

  parent->addChild(this);
}

void ChangeNode::addChild(ChangeNode* child) {
  children.emplace_back(child);
}

int ChangeNode::restore_state(state_t& state) {
  for (const auto& stack_change : stack_changes) {
    std::memcpy(state.stack.content + stack_change.first * sizeof(uint64_t), &(stack_change.second), sizeof(uint64_t)); 
  }

  for (const auto& heap_change : heap_changes) {
    std::memcpy(state.heap.content + heap_change.first * sizeof(uint64_t), &(heap_change.second), sizeof(uint64_t)); 
  }

  state.addr = this->get_addr();
  state.regs = this->regs;

  return 1;
}

uint32_t ChangeNode::get_id() {
  return id;
}

uint64_t ChangeNode::get_addr() {
  return regs.get_pc(); 
}


ExecHistory::ExecHistory() {
  //state_log = {};
  //ctree_root = nullptr;
  root_node = nullptr;
  current_state = nullptr;
}

void ExecHistory::set_root(state_t& state) {
  root_node = new ChangeNode(state);
  current_state = root_node;
  return;
}

// WARNING: same as log_goto for now
void ExecHistory::log(state_t& state) {
  if (current_state == nullptr) {
    return;
  }

  ChangeNode* next_node = new ChangeNode(current_state, state);
  current_state = next_node;
}

void ExecHistory::log_goto(state_t& state) {
  if (current_state == nullptr) {
    return;
  }

  ChangeNode* next_node = new ChangeNode(current_state, state);
  current_state = next_node;
}

int ExecHistory::restore_state_by_id(uint32_t n, state_t& state) {
  // bfs for id
  std::deque<ChangeNode*> queue; 

  queue.push_back(root_node);
  std::vector<uint32_t> known_nodes = {root_node->get_id()};


  while (!queue.empty()) {
    auto current_node = queue.front();
    queue.pop_front();
    if (current_node->get_id() == n) {
      return current_node->restore_state(state);
    }
    
    queue.insert(queue.end(), current_node->children.begin(), current_node->children.end());
  }

  return 0;
}


std::string ExecHistory::str() const {
  std::stringstream ss;

  std::deque<ChangeNode*> queue;
  queue.push_back(root_node);
  std::vector<uint32_t> known_nodes = {root_node->get_id()};

  while (!queue.empty()) {
    auto current_node = queue.front();
    queue.pop_front();
    ss << "Checkpoint nr. " << current_node->get_id() << " at PC: " << fmt::addr_64(current_node->get_addr()) <<  std::endl;
    queue.insert(queue.end(), current_node->children.begin(), current_node->children.end());
  }

  return ss.str();   
}
