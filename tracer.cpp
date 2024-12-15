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
  //children = {};
  main = nullptr;
  branch = nullptr;

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
  //children = {};
  main = nullptr;
  branch = nullptr;

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
    if (root_heap_content[i] != heap_words[i]) {
      heap_changes[i] = heap_words[i];
    }
  }

  for (size_t i = 0; i < heap.size/sizeof(uint64_t); i++) {
    if (root_stack_content[i] != stack_words[i]) {
      stack_changes[i] = stack_words[i];
    }
  }

  //parent->addChild(this);
  parent->main = this;
  branch_id = parent->branch_id;
}

ChangeNode::ChangeNode(ChangeNode* origin) {
  stack_changes = origin->stack_changes;
  heap_changes = origin->heap_changes;

  parent = nullptr;
  regs = origin->regs;

  addr = origin->get_addr();
  id = 0;
  root_heap_start = origin->root_heap_start;
  root_heap_size = origin->root_heap_size;
  root_heap_content =  origin->root_heap_content;

  root_stack_start = origin->root_stack_start;
  root_stack_size = origin->root_stack_size;
  root_stack_content =  origin->root_stack_content;

  main = nullptr;
  branch = nullptr;
}

void ChangeNode::make_branch(uint32_t id) {
  this->branch = new ChangeNode(this);
  this->branch->set_parent(this);

  this->branch->set_id(id);
  this->branch->set_branch_id(branch_id+1);
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

void ChangeNode::set_branch_id(uint32_t id) {
  this->branch_id = id;
}

void ChangeNode::set_parent(ChangeNode* parent) {
  this->parent = parent;
}

void ChangeNode::set_main(ChangeNode* main) {
  this->main = main;
}

void ChangeNode::set_branch(ChangeNode* branch) {
  this->branch = branch;
}

void ChangeNode::set_id(uint32_t id) {
  this->id = id;
}

uint32_t ChangeNode::get_id() {
  return id;
}

uint32_t ChangeNode::get_branch_id() {
  return branch_id;
}

uint64_t ChangeNode::get_addr() {
  return regs.get_pc(); 
}



ExecHistory::ExecHistory() {
  tree_size = 0;
  root_node = nullptr;
  current_state = nullptr;
}

void ExecHistory::set_root(state_t& state) {
  root_node = new ChangeNode(state);
  current_state = root_node;

  current_state->set_id(tree_size);
  return;
}

void ExecHistory::log_goto(state_t& state) {
  if (current_state == nullptr) {
    return;
  }

  if (current_state->main != nullptr ) {
    if (current_state->branch == nullptr) {
      branch_numbers++;
      tree_size++;
      current_state->make_branch(tree_size);

      color_tree(root_node, 0);
    }
    current_state = current_state->branch;
    return log_goto(state);
  }

  ChangeNode* next_node = new ChangeNode(current_state, state);
  current_state = next_node;
  tree_size++;
  current_state->set_id(tree_size);
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
      this->current_state = current_node;
      return current_node->restore_state(state);
    }

    if (current_node->main != nullptr) {
      queue.push_back(current_node->main); 
    }

    if (current_node->branch != nullptr) {
      queue.push_back(current_node->branch); 
    }
  }

  return 0;
}


uint32_t ExecHistory::color_tree(ChangeNode* start, uint32_t n) {
  // skip to end;
  ChangeNode* current_node = start;
  while (current_node->main != nullptr) {
    current_node->set_branch_id(n);
    current_node = current_node->main;
  }

  current_node->set_branch_id(n);

  while (current_node != start) {
    if (current_node->branch != nullptr) {
      n = color_tree(current_node->branch, n+1);
    }
    current_node = current_node->parent;
  }

  return n;
}

void ExecHistory::subtree_str(ChangeNode* start, std::stringstream& out, std::string prefix) const {
  if (start == nullptr) {
    return;
  }
  std::deque< std::pair<ChangeNode*, std::string> > branches;
  out << prefix;
  if (prefix != "") {
    out << "\\";
  }

  std::stringstream current_prefix;
  current_prefix << prefix; 

  uint32_t n = start->get_branch_id();
  while (start != nullptr) {
    out << start->get_id() << "-";

    if (start->branch != nullptr) {
      branches.emplace_back(std::pair<ChangeNode*, std::string> (start->branch, current_prefix.str()));
    }

    current_prefix << "  ";
    start = start->main;
  }

  out << "     branch: " << n << std::endl;

  int i = 0;
  while (!branches.empty()) {
    auto next = branches.front();
    branches.pop_front();

    subtree_str(next.first, out, next.second);
    i++;
  }
}

void ExecHistory::get_path(ChangeNode* start, std::vector<uint32_t>& ids, uint32_t n, uint32_t branch_count) const {
  if (start->main == nullptr) {
    //path << start->get_id() << "-    branch: " << n;
    ids.emplace_back(start->get_id());
    return;
  }

  //path << start->get_id() << "-";
  std::cout << "branch: " << n <<  " at id: " <<  start->get_id() << std::endl;
  ids.emplace_back(start->get_id());

  if (start->branch == nullptr) {
    return get_path(start->main,ids, n, branch_count); 
  } else {
    if (n & (1 << branch_count)) {
     return get_path(start->branch, ids, n, branch_count+1); 
    }

    return get_path(start->main, ids, n, branch_count+1); 
  }
}

std::string ExecHistory::str() const {
  std::stringstream ss;
  if (root_node == nullptr) {
    return ss.str();
  }


  subtree_str(root_node, ss,  "");
  /*
  bool printed_ids[tree_size];
  std::vector<uint32_t> path;

  for (uint32_t i = 0; i <= branch_numbers; i++) {
    path.clear();

    //std::cout << i << std::endl;
    get_path(root_node, path, i, 0);
    

    uint32_t idx = 0;
    while (printed_ids[path[idx]]) {
      ss << "  "; 
      idx += 1;
    }

    if (path.size() <= idx) {
      continue;
    }
    printed_ids[path[idx]] = true;
    ss << "\\";

    for (uint32_t id = idx; id < path.size(); id++) {
        ss << path[id] << "-";
        printed_ids[path[id]] = true;
    }
    ss << "  branch: " << i << std::endl;
  }*/
  return ss.str();   
}
