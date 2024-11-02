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

#include <readline/readline.h>
#include <readline/history.h>

command_t get_cmd() { 
  command_t ret;
  std::string cmd;


  char *inpt = NULL;
  inpt = readline("wg> ");
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

  std::cout << "hi" << std::endl;
  for (int i = 1; i < argc; i++) {
    if (std::string(argv[i]) == "-c") {
      std::cout << "starting in console mode" << std::endl;
    } else {
      if (filename == nullptr) {
        std::cout << argv[i] << std::endl;
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
      dbg.reset();
    } else if (cmd.cmd == "b") {
      if (cmd.args.size() >= 2) {
        const char *hex_addr = cmd.args[1].c_str();
        uint64_t bp_addr = strtol(hex_addr, NULL, 16);

        dbg.set_breakpoint(bp_addr);

        std::cout << "bp set at: " << std::hex << bp_addr << std::endl;
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
        }
      }
    } else if (cmd.cmd == "xl") {
      if (cmd.args.size() == 3) {
        uint64_t addr = std::strtol(cmd.args[1].c_str(), NULL, 16);
        size_t n = std::stoi(cmd.args[2].c_str());
        auto content = dbg.get_long(addr, n);

        if (content.size() != n) {
          std::cout << "could not read data" << std::endl;
          continue;
        }

        for (size_t i = 0; i < n; i++) {
          std::cout << "0x" << std::hex << addr + i*8 << ": 0x" << std::hex << content[i] << std::endl;
        }
      }
    } else if (cmd.cmd == "xw") {
      if (cmd.args.size() == 3) {
        uint64_t addr = std::strtol(cmd.args[1].c_str(), NULL, 16);
        size_t n = std::stoi(cmd.args[2].c_str());
        auto content = dbg.get_word(addr, n);

        if (content.empty()) {
          std::cout << "could not read data" << std::endl;
          continue;
        }
        for (size_t i = 0; i < n; i++) {
          std::cout << "0x" << std::hex << addr + i*4 << ": 0x" << std::hex << content[i] << std::endl;
        }
      }
    } else if (cmd.cmd == "D") {
      if (cmd.args.size() == 2) {
        uint64_t addr = std::stoul(cmd.args[1].c_str(), NULL, 16);
        dbg.delete_breakpoint(addr);
        std::cout << "deleted breakpoint at: 0x" << std::hex << addr << std::endl;
      }
    } else if (cmd.cmd == "dw") {
      if (cmd.args.size() == 3) {
        size_t n = std::stoi(cmd.args[2].c_str());
        uint64_t addr =  std::stoul(cmd.args[1].c_str(), NULL, 16);

        std::cout << "disassembling " << std::hex << addr  << ":" << std::endl; 

        auto instructions = dbg.disassemble(addr, 4*n);

        for (auto instr: instructions) {
          std::cout << instr.str() << std::endl;
        }

      } 
    } else if (cmd.cmd == "db") {
      if (cmd.args.size() == 3) {
        size_t n = std::stoi(cmd.args[2].c_str());
        uint64_t addr =  std::strtol(cmd.args[1].c_str(), NULL, 16);

        std::cout << "disassembling " << std::hex << addr  << ":" << std::endl; 

        auto instructions = dbg.disassemble(addr, n);

        for (auto instr: instructions) {
          std::cout << instr.str() << std::endl;
        }

      }
    } else if (cmd.cmd == "ds") {
      if (cmd.args.size() == 2) {
        std::string symbol = cmd.args[1];

        std::cout << "disassembling " << symbol  << ":" << std::endl; 
        auto instructions = dbg.disassemble(symbol); 

        for (auto instr: instructions) {
          std::cout << instr.str() << std::endl;
        }
        //}
      }
    } else if (cmd.cmd == "vmmap") {
      dbg.print_vmmap();

    } else if (cmd.cmd == "quit") {
      break;
    }
  }
}
