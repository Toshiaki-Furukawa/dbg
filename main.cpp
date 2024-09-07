#include <string>
#include <iostream>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <vector>
#include <signal.h>

#include <sstream>
#include <fstream>

#include <cstdint>
#include <map>
#include "elftypes.hpp"
#include "elf.hpp"
#include "dbgtypes.hpp"
#include "dbg.hpp"

command_t get_cmd() { 
  command_t ret;
  std::string cmd;

  std::getline(std::cin, cmd);
  if (cmd == "") {
    return ret;
  }

  std::size_t start = cmd.find_first_not_of(' ', 0);
  std::size_t end = cmd.find(' ', start);

  ret.cmd = cmd.substr(start,  end-start);
    
  while ((start = cmd.find_first_not_of(' ', end)) != std::string::npos) {
    end = cmd.find(' ', start);
    ret.args.emplace_back(cmd.substr(start, end-start));
  }
  
  return ret;
}

int main(int argc, char *argv[]) {
  // setup
  if (argc < 2) {
    std::cout << "Usage: ./dbg filename" << std::endl;
    return 0;
  }

  const char *filename = argv[1];

  // run
  Debugger dbg = Debugger(filename);
  int ret_sig = 1;
 
  while (true) {
    std::cout << "wg> ";
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
      if (!cmd.args.empty()) {
        const char *hex_addr = cmd.args[0].c_str();
        uint64_t bp_addr = strtol(hex_addr, NULL, 16);
             
        dbg.set_breakpoint(bp_addr);

        std::cout << "bp set at: " << std::hex << bp_addr << std::endl;
      }
    } else if  (cmd.cmd == "s") {
      dbg.single_step(); 
      dbg.print_regs();
    
    } else if (cmd.cmd == "i") {
      if (!cmd.args.empty()) {
        if (cmd.args[0] == "bps") {
          dbg.list_breakpoints();
        } else if (cmd.args[0] == "regs") {
          dbg.print_regs();
        } else if (cmd.args[0] == "symbols" || cmd.args[0] == "sym" || cmd.args[0] == "functions") {
          dbg.print_symbols();
        } else if (cmd.args[0] == "sections" || cmd.args[0] == "sec") {
          dbg.print_sections();
        }
      }
    } else if (cmd.cmd == "xl") {
      if (cmd.args.size() == 2) {
        uint64_t addr = std::strtol(cmd.args[0].c_str(), NULL, 16);
        size_t n = std::stoi(cmd.args[1].c_str());
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
      if (cmd.args.size() == 2) {
        uint64_t addr = std::strtol(cmd.args[0].c_str(), NULL, 16);
        size_t n = std::stoi(cmd.args[1].c_str());
        auto content = dbg.get_word(addr, n);

        if (content.size() != 2*n) {
          std::cout << "could not read data" << std::endl;
          continue;
        }

        for (size_t i = 0; i < 2*n; i++) {
          std::cout << "0x" << std::hex << addr + i*4 << ": 0x" << std::hex << content[i] << std::endl;
        }
      }
    } else if (cmd.cmd == "D") {
      if (!cmd.args.empty()) {
        uint32_t idx = atoi(cmd.args[0].c_str());
        dbg.delete_breakpoint(idx);
        std::cout << "deleted breakpoint nr.: " << idx << std::endl;
      }
    } else if (cmd.cmd == "dw") {
      if (cmd.args.size() == 2) {
        size_t n = std::stoi(cmd.args[1].c_str());
        uint64_t addr =  std::strtol(cmd.args[0].c_str(), NULL, 16);
        
        dbg.disassemble(addr, 4*n);
      } 
    } else if (cmd.cmd == "db") {
      if (cmd.args.size() == 2) {
        size_t n = std::stoi(cmd.args[1].c_str());
        uint64_t addr =  std::strtol(cmd.args[0].c_str(), NULL, 16);
        
        dbg.disassemble(addr, n);
      }
    } else if (cmd.cmd == "ds") {
      if (cmd.args.size() == 1) {
        std::string symbol = cmd.args[0];
        //uint64_t addr = dbg.get_symbol_addr(symbol);
        //uint32_t size = dbg.get_symbol_size(symbol);
        //std::cout << symbol << " at: 0x" <<  std::hex << addr << std::endl;

        //if (addr != 0) {
        dbg.disassemble(symbol); 
        //}
      }
    } else if (cmd.cmd == "vmmap") {
      dbg.print_vmmap();
    
    } else if (cmd.cmd == "quit") {
      break;
    }
  }
}
