#include <string>
#include <iostream>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <vector>
#include <signal.h>
#include  <filesystem>

#include <sstream>
#include <fstream>

#include <cstdint>
#include <map>
#include "elftypes.hpp"
#include "elf.hpp"
#include "dbgtypes.hpp"
#include "dbg.hpp"
#include "disass.hpp"
#include "fmt.hpp"

#include <readline/readline.h>
#include <readline/history.h>

enum MATH_OP {
  ADD,
  SUB,
  MUL,
  DIV,
  BRA_OPEN,
  BRA_CLOSE
};

command_t get_cmd() { 
  command_t ret;
  std::string cmd;


  char *inpt = NULL;
  //std::cout << fmt::green << "wg> " << fmt::endc;
  inpt = readline("\033[32mwg> \033[0m");
  add_history(inpt);

  std::stringstream ss {inpt};
  std::string item;

  // split
  while(std::getline(ss, item, ' ')) {
    ret.args.push_back(item);
  }

  if (!ret.args.empty()) { 
    ret.cmd = ret.args[0];
  }

  return ret;
}


uint64_t eval_op(uint64_t a, uint64_t b, MATH_OP op) {
  if (op == ADD) {
    return a + b;
  } else if (op == MATH_OP::SUB) {
    return a - b;
  } else if (op == MATH_OP::MUL) {
    return a * b;
  } else if (op == MATH_OP::DIV) {
    return a / b;
  } else {
    return 0;
  }
}

bool is_opchar(std::string str, size_t idx) {
  if (str[idx] != '+' && str[idx] != '-' && str[idx] != '*' && str[idx] != '/' && str[idx] != '(' && str[idx] != ')') {
    return false;
  }
  return true;
}

std::string get_word(std::string str, size_t idx) {
  std::string terminal;

  while (idx < str.size() && !is_opchar(str, idx)) {
    terminal += str[idx];
    idx++;
  }

  return terminal;
}


uint64_t eval(Debugger& dbg, std::string expr, size_t& n_bytes) {
  std::vector<uint64_t> values;
  std::vector<MATH_OP> ops;
  
  n_bytes = 1;

  for (size_t i = 0; i < expr.size(); i++) { 
    if (expr[i] == '(') {
      ops.push_back(MATH_OP::BRA_OPEN); 
    }  else if (expr[i] == ')') {
      while (!ops.empty() && ops.back() != MATH_OP::BRA_OPEN) {
        auto a = values.back();
        values.pop_back();
        auto b = values.back();
        values.pop_back();

        MATH_OP op = ops.back();
        ops.pop_back();
        values.push_back(eval_op(a, b, op));
      }

      if (!ops.empty()) {
        ops.pop_back();
      }
    } else if (expr[i] == '*' || expr[i] == '/') {
      if (expr[i] == '*') {
        ops.push_back(MATH_OP::MUL);
      } else if (expr[i] == '/') {
        ops.push_back(MATH_OP::DIV);
      }
    } else if (expr[i] == '+' || expr[i] == '-') {
      while (!ops.empty() && (ops.back() == MATH_OP::MUL || ops.back() == MATH_OP::DIV)) {
        auto a = values.back();
        values.pop_back();
        
        auto b = values.back();
        values.pop_back();

        MATH_OP op = ops.back();
        ops.pop_back();
        values.push_back(eval_op(a, b, op));
      } 
      
      if (expr[i] == '+') {
        ops.push_back(MATH_OP::ADD);
      } else if (expr[i] == '-') {
        ops.push_back(MATH_OP::SUB);
      }
    } else {
      std::string terminal = get_word(expr, i);
      uint64_t addr = 0;

      if (terminal.starts_with("0x")) {
        addr = std::strtol(terminal.c_str(), NULL, 16);
      } else if (std::strtol(terminal.c_str(), NULL, 10) != 0) {
        addr = std::strtol(terminal.c_str(), NULL, 10);
      } else if (dbg.get_reg(terminal) != 0) {
        addr = dbg.get_reg(terminal);
      } else {
        addr = dbg.get_symbol_addr(terminal);

        n_bytes = (n_bytes == 1) ? addr : n_bytes;
      }

      i += terminal.size() - 1;
      values.push_back(addr);
    }
  }

  // TODO: fix subtraction 
 
  while (!ops.empty()) {
    auto a = values.back();
    values.pop_back();
        
    auto b = values.back();
    values.pop_back();

    MATH_OP op = ops.back();
    ops.pop_back();
    values.push_back(eval_op(a, b, op));
  } 

  return values.back();
}



int main(int argc, char *argv[]) {
  // test
  if (argc < 2) {
    std::cout << "Usage: ./dbg filename" << std::endl;
    return 0;
  }

  bool console_mode = false;
  const char *filename = nullptr;

  for (int i = 1; i < argc; i++) {
    if (std::string(argv[i]) == "-c") {
      std::cout << "starting in console mode" << std::endl;
    } else {
      if (filename == nullptr) {
        filename = argv[i];
      }  
    }
  }

  //const char *filename = argv[1];
  if (!std::filesystem::exists(filename)) {
    std::cout << "file does not exist" << std::endl;
    return 0;
  }

  // run
  Debugger dbg = Debugger(filename);
  int ret_sig = 1;

  while (true) {
    command_t cmd = get_cmd();

    if (cmd.cmd == "c") {
      ret_sig = dbg.cont();
      if (ret_sig == 0) {
        std::cout << "program exited.." << std::endl;
      } else if (ret_sig == 1) {
        std::cout << "hit breakpoint.." << std::endl;
      } else if (ret_sig == -1) {
        std::cout << "error occured. Aborting" << std::endl;
        exit(-1);
      }
    } else if (cmd.cmd == "r") {
      if (cmd.args.size() == 2) {
        uint32_t n = std::strtol(cmd.args[1].c_str(), NULL, 10);
        std::cout << "trying to restore nr. " << n << std::endl;
        
        dbg.restore_state(n); 
      } else {
        dbg.reset();
      }
    } else if (cmd.cmd == "log") {
      dbg.log_state(); 
    } else if (cmd.cmd == "b") {
      if (cmd.args.size() == 2) {
        /*uint64_t addr = 0;

        if (cmd.args[1].starts_with("0x")) {
          addr = std::strtol(cmd.args[1].c_str(), NULL, 16);
        } else {
          addr = dbg.get_symbol_addr(cmd.args[1]);
        }
        if (addr == 0) {
          std::cout << "Invalid position!" << std::endl;
          continue;
        }*/
        uint64_t addr = 0;
        size_t sym_size = 1;
        addr = eval(dbg, cmd.args[1], sym_size);

        if (addr == 0) {
          std::cout << "Invalid position!" << std::endl;
          continue;
        }

        dbg.set_breakpoint(addr);

        std::cout << "Breakpoint set at: " << fmt::yellow << "0x" << std::hex << addr << fmt::endc << std::endl;
      }
    } else if  (cmd.cmd == "s") {
      dbg.single_step(); 
      std::cout << "pc at: 0x" << std::hex << dbg.get_pc() << std::endl;
    } else if (cmd.cmd == "i") {
      if (cmd.args.size() == 2) {
        if (cmd.args[1] == "bps") {
          dbg.list_breakpoints();
        } else if (cmd.args[1] == "regs") {
          dbg.print_regs();
        } else if (cmd.args[1] == "symbols" || cmd.args[1] == "sym" || cmd.args[1] == "functions") {
          dbg.print_symbols();
        } else if (cmd.args[1] == "sections" || cmd.args[1] == "sec") {
          dbg.print_sections();
        } else if (cmd.args[1] == "history" || cmd.args[1] == "hist") {
          dbg.print_history();
        }
      }
    } else if (cmd.cmd == "xl") {
      std::vector<uint64_t> content = {};
      size_t n = 1;
      uint64_t addr = 0;
      if (cmd.args.size() == 2) {
        addr = eval(dbg, cmd.args[1], n);
        content = dbg.get_long(addr, n);

      } else if (cmd.args.size() == 3) {
        n = std::strtol(cmd.args[2].c_str(), NULL, 10);

        size_t tmp = 1;

        addr = eval(dbg, cmd.args[1], tmp);
        content = dbg.get_long(addr, n);
      }

      if (content.size() != n) {
        std::cout << "could not read data" << std::endl;
        continue;
      }
      
      uint64_t counter = 0;
      for (const auto& val : content) {
        std::cout << fmt::yellow << "0x" << std::hex << (addr + counter) << fmt::endc << ": " << fmt::addr_64(val) << std::endl;
        counter += 8;
      }
    } else if (cmd.cmd == "xw" || cmd.cmd == "x") {
      std::vector<uint32_t> content = {};

      size_t n = 1;
      uint64_t addr = 0;
      if (cmd.args.size() == 2) {
        addr = eval(dbg, cmd.args[1], n);
        content = dbg.get_word(addr, n);

      } else if (cmd.args.size() == 3) {
        n = std::strtol(cmd.args[2].c_str(), NULL, 10);

        size_t tmp = 1;

        addr = eval(dbg, cmd.args[1], tmp);
        content = dbg.get_word(addr, n);
      }

      if (content.size() != n) {
        std::cout << "could not read data" << std::endl;
        continue;
      }
      
      uint64_t counter = 0;
      for (const auto& val : content) {
        std::cout << fmt::yellow << "0x" << std::hex << (counter + addr)  << fmt::endc << ": " << fmt::addr_32(val) << std::endl;
        counter += 4;
      }
    } else if (cmd.cmd == "D") {
      if (cmd.args.size() == 2) {
        uint64_t addr = std::stoul(cmd.args[1].c_str(), NULL, 16);
        dbg.delete_breakpoint(addr);
        std::cout << "deleted breakpoint at: 0x" << std::hex << addr << std::endl;
      }
    } else if (cmd.cmd == "ds" || cmd.cmd == "disass" || cmd.cmd == "disassemble") {
      // DISASSEMBLE STUFF
      std::vector<Instruction> instructions;

      if (cmd.args.size() == 2) {
        if (cmd.args[1].starts_with("0x")) {
          auto addr = std::strtol(cmd.args[1].c_str(), NULL, 16);

          instructions = dbg.disassemble(addr, 4);
        } else if (dbg.get_reg(cmd.args[1]) != 0) {
          auto addr = dbg.get_reg(cmd.args[1]);

          instructions = dbg.disassemble(addr, 4);
        } else {
          instructions = dbg.disassemble(cmd.args[1]);
        }

      } else if (cmd.args.size() == 3) {
        size_t n = std::strtol(cmd.args[2].c_str(), NULL, 10);

        if (cmd.args[1].starts_with("0x")) {
          uint64_t addr = std::strtol(cmd.args[1].c_str(), NULL, 16);

          instructions = dbg.disassemble(addr, n);
        } else if (dbg.get_reg(cmd.args[1]) != 0) {
          auto addr = dbg.get_reg(cmd.args[1]);

          instructions = dbg.disassemble(addr, n);
        } else {
          auto addr = dbg.get_symbol_addr(cmd.args[1]);
          if (addr != 0) {
            instructions = dbg.disassemble(addr, n);
          }
        }
      }

      for (const auto& instr: instructions) {
        std::cout << instr.str() << std::endl;
      }
    } else if (cmd.cmd == "vmmap") {
      dbg.print_vmmap();

    } else if (cmd.cmd == "quit") {
      break;
    }
  }
}
