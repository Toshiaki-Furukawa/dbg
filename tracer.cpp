#include <vector>
#include <string>
#include <sstream>
#include <cstdint>
#include <iostream>

#include "dbgtypes.hpp"
#include "tracer.hpp"
#include "fmt.hpp"

ExecHistory::ExecHistory() {
  state_log = {};
}

void ExecHistory::log(state_t state) {
  state_log.emplace_back(state); 
}

bool ExecHistory::is_logged(uint64_t addr) {
  for (const auto& state : state_log) {
    if (state.addr == addr) {
      return true;
    }
  }

  return false;
}

chunk_t* ExecHistory::get_stack(uint32_t n) {
  if (n >= state_log.size()) {
    return nullptr;
  }

  if (state_log[n].stack.start == 0x0) {
    return nullptr;
  }
  return &(state_log[n].stack);
}

chunk_t* ExecHistory::get_heap(uint32_t n) {
  if (n >= state_log.size()) {
    return nullptr;
  }

  if (state_log[n].heap.start == 0x0) {
    return nullptr;
  }
  return &(state_log[n].heap);
}

Registers* ExecHistory::get_registers(uint32_t n) {
  std::cout << "HI" << std::endl;
  if (n >= state_log.size()) {
    std::cout << "HI2" << std::endl;
    return nullptr;
  }

  return &(state_log[n].regs);
}

std::string ExecHistory::str() const {
  std::stringstream ss;
  int idx = 0;
  for (const auto& state : state_log) {
    ss << "Checkpoint nr. " << idx << " at PC: " << fmt::addr_64(state.addr) <<  std::endl;
    ss << "   heap: " << fmt::addr_64(state.heap.start) << std::endl;
    ss << "   stack: " << fmt::addr_64(state.stack.start) << std::endl << std::endl;
  } 
  return ss.str();   
}
