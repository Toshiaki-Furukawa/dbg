#include <vector>
#include <string>
#include <sstream>
#include <cstdint>
#include <iostream>
#include <memory>
#include <deque>

#include "dbgtypes.hpp"
#include "tracer.hpp"
#include "fmt.hpp"


ExecHistory::ExecHistory() {
  //state_log = {};
  //ctree_root = nullptr; 
  current_state = nullptr;
}

void ExecHistory::set_root(state_t& state) {
  //if (current_state == nullptr) {
  ctree_root.state = std::make_shared<state_t> (state);
  ctree_root.id = 0;
  ctree_root.children = {};
  current_state = &ctree_root; //std::make_shared<cnode_t> (ctree_root);
  //}
  return;
}

void ExecHistory::log(state_t& state) {
  cnode_t* node = new cnode_t; 
  node->state = std::make_shared<state_t> (state);
  node->id = current_state->id;
  node->children = {};

  current_state->children.emplace_back(node);
}

void ExecHistory::log_goto(state_t& state) {
  if (current_state == nullptr) {
    return;
  }

  cnode_t *node = new cnode_t; 
  node->state = std::make_shared<state_t> (state);
  std::cout << "hi" << std::endl;
  node->id = current_state->id + 1;
  node->children = {};

  current_state->children.emplace_back(node);
  std::cout << "current_state: " << current_state->children.size() << std::endl;
  current_state = node; // goto point
}

state_t* ExecHistory::get_state_by_id(uint32_t n) {
  // bfs for id
  std::deque<const cnode_t*> queue; 

  queue.push_back(&ctree_root);
  std::vector<uint32_t> known_nodes = {ctree_root.id};

  while (!queue.empty()) {
    auto current_node = queue.front();
    queue.pop_front();
    if (current_node->id == n) {
      return current_node->state.get();
    }
    
    queue.insert(queue.end(), current_node->children.begin(), current_node->children.end());
  }
  return nullptr;
}


std::string ExecHistory::str() const {
  std::stringstream ss;

  std::deque<const cnode_t*> queue;
  queue.push_back(&ctree_root);
  std::vector<uint32_t> known_nodes = {ctree_root.id};

  while (!queue.empty()) {
    auto current_node = queue.front();
    queue.pop_front();
    ss << "Checkpoint nr. " << current_node->id << " at PC: " << fmt::addr_64(current_node->state->addr) <<  std::endl;
    queue.insert(queue.end(), current_node->children.begin(), current_node->children.end());
  }

  return ss.str();   
}
