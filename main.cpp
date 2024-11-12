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

command_t get_cmd() { 
  command_t ret;
  std::string cmd;


  char *inpt = NULL;
  std::cout << fmt::green << "wg> " << fmt::endc;
  inpt = readline(" ");
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
        uint64_t addr = 0;

        if (cmd.args[1].starts_with("0x")) {
          addr = std::strtol(cmd.args[1].c_str(), NULL, 16);
        } else {
          addr = dbg.get_symbol_addr(cmd.args[1]);
        }
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
        if (cmd.args[1].starts_with("0x")) {
          addr = std::strtol(cmd.args[1].c_str(), NULL, 16);

          content =  dbg.get_long(addr, n);
        } else if (dbg.get_reg(cmd.args[1]) != 0) {
          addr = dbg.get_reg(cmd.args[1]);

          content =  dbg.get_long(addr, n);
        } else {
          addr = dbg.get_symbol_addr(cmd.args[1]);
          
          content = dbg.get_long(addr, n);
        }
      } else if (cmd.args.size() == 3) {
        n = std::strtol(cmd.args[2].c_str(), NULL, 10);

        if (cmd.args[1].starts_with("0x")) {
          addr = std::strtol(cmd.args[1].c_str(), NULL, 16);

          content =  dbg.get_long(addr, n);
        } else if (dbg.get_reg(cmd.args[1]) != 0) {
          addr = dbg.get_reg(cmd.args[1]);

          content =  dbg.get_long(addr, n);
        } else {
          addr = dbg.get_symbol_addr(cmd.args[1]);
          
          content = dbg.get_long(addr, n);
        }
      }

      if (content.size() != n) {
        std::cout << "could not read data" << std::endl;
        continue;
      }
      
      int counter = 0;
      for (const auto& val : content) {
        std::cout << fmt::yellow << "0x" << std::hex << (addr + counter) << fmt::endc << ": " << fmt::addr_64(val) << std::endl;
        counter += 8;
      }
    } else if (cmd.cmd == "xw" || cmd.cmd == "x") {
      std::vector<uint32_t> content = {};

      size_t n = 1;
      uint64_t addr = 0;
      if (cmd.args.size() == 2) {
        if (cmd.args[1].starts_with("0x")) {
          addr = std::strtol(cmd.args[1].c_str(), NULL, 16);

          content =  dbg.get_word(addr, n);
        } else if (dbg.get_reg(cmd.args[1]) != 0) {
          addr = dbg.get_reg(cmd.args[1]);

          content =  dbg.get_word(addr, n);
        } else {
          addr = dbg.get_symbol_addr(cmd.args[1]);
          
          content = dbg.get_word(addr, n);
        }
      } else if (cmd.args.size() == 3) {
        n = std::strtol(cmd.args[2].c_str(), NULL, 10);

        if (cmd.args[1].starts_with("0x")) {
          addr = std::strtol(cmd.args[1].c_str(), NULL, 16);

          content =  dbg.get_word(addr, n);
        } else if (dbg.get_reg(cmd.args[1]) != 0) {
          addr = dbg.get_reg(cmd.args[1]);

          content =  dbg.get_word(addr, n);
        } else {
          addr = dbg.get_symbol_addr(cmd.args[1]);
          
          content = dbg.get_word(addr, n);
        }
      }

      if (content.size() != n) {
        std::cout << "could not read data" << std::endl;
        continue;
      }
      
      int counter = 0;
      for (const auto& val : content) {
        std::cout << fmt::yellow << "0x" << std::hex << (addr + counter) << fmt::endc << ": " << fmt::addr_32(val) << std::endl;
        counter += 8;
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
