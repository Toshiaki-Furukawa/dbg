#include <unistd.h>
#include <stdio.h>
#include <string>
#include <stdint.h>
#include <iostream>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <vector>
#include <signal.h>

#include "elf.cpp"

struct command {
  std::string cmd;
  std::vector<std::string> args;
} typedef command_t;

class Breakpoint {
    uint64_t addr;
    //unsigned long data;
    uint8_t data;
    bool active; 

public:
  Breakpoint(uint64_t bp_addr, uint8_t orig_data) : addr(bp_addr), data(orig_data), active(true)
  {}
  
  unsigned long get_addr() const {
    return addr;
  } 
  
  unsigned long get_data() const {
    return data;
  }

  unsigned long get_mod_data() const {
    unsigned long new_data = ((data & ~0xff) | 0xcc);
    return new_data;
  }

  void enable() {
    active = true;
  }

  void disable() {
    active = false;
  }
};



class Debugger {
  std::vector<Breakpoint> breakpoints;
  user_regs_struct regs;
  pid_t proc;
  int status;
  siginfo_t signal;
  ELF elf;
  const char *filename;
  bool is_running;

  /*void restore(Breakpoint bp) {
    ptrace(PTRACE_POKEDATA, proc, bp.get_addr(), bp.get_data());
  }*/
  
  void enable_breakpoint(Breakpoint *bp) {
    //unsigned long data = ptrace(PTRACE_PEEKDATA, proc, addr, NULL);
    //std::cout << "data at: " << std::hex << data << std::endl;
    //unsigned long new_data = ((data & ~0xff) | 0xcc); // set breakpoint
    if (!is_running) {
      return;
    }

    auto data = ptrace(PTRACE_PEEKDATA, proc, bp->get_addr(), NULL);
    auto mod_data = ((data & ~0xff) | 0xcc);
    
    ptrace(PTRACE_POKEDATA, proc, bp->get_addr(), mod_data);
    bp->enable();
  }

  void disable_breakpoint(Breakpoint *bp) {
    if (!is_running) {
      return;
    }
    auto data = ptrace(PTRACE_PEEKDATA, proc, bp->get_addr(), NULL);
    auto orig_data = ((data & ~0xff) | bp->get_data());

    ptrace(PTRACE_POKEDATA, proc, bp->get_addr(), orig_data);

    bp->disable(); 
  }

  int update_regs() {
    if (ptrace(PTRACE_GETREGS, proc, NULL, &regs) == -1) {
      std::cout << "could not load registers";
      return -1;
    } 
    return 1;
  }

public:
  Debugger (const char *filename) : filename(filename), elf(filename) {
    proc = fork();
    if (proc == -1) {
      std::cout << "Error while forking" << std::endl;  
      exit(-1);
    }
  
    if (proc == 0) {
      personality(ADDR_NO_RANDOMIZE);

      ptrace(PTRACE_TRACEME, proc, NULL, NULL);

      execl(filename, filename, NULL, NULL);
    } else {
      waitpid(proc, &status, 0);
      ptrace(PTRACE_SETOPTIONS, proc, NULL, PTRACE_O_EXITKILL);
      is_running = true;
      return;
    }
  }

  void reset() {          // WARNING: not working
    kill(proc, SIGKILL);
    waitpid(proc, &status, 0);

    if (WIFSIGNALED(status)) {
      std::cout << "tracee killed" << std::endl;
    }
   
    proc = fork();
    if (proc == -1) {
      std::cout << "Error while forking new process" << std::endl;
      exit(-1);
    }

    if (proc == 0) {
      personality(ADDR_NO_RANDOMIZE);

      ptrace(PTRACE_TRACEME, proc, NULL, NULL);

      execl("test/test", "test/test", NULL, NULL);
    } else {
      waitpid(proc, &status, 0);
      ptrace(PTRACE_SETOPTIONS, proc, NULL, PTRACE_O_EXITKILL);
      is_running = true;
      update_regs();

      for (Breakpoint bp: breakpoints) {
        enable_breakpoint(&bp);
      }

      return;
    }
  }

  int cont() {
    ptrace(PTRACE_CONT, proc, NULL, NULL);

    waitpid(proc, &status, 0);
    if (WIFEXITED(status)) {
      is_running = false;
      return 0;
    }
    
    update_regs();

    if (ptrace(PTRACE_GETSIGINFO, proc, NULL, &signal)  == -1) {
      std::cout << "cant decode signal..." << std::endl;
      return -1;
    }

    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
      for (Breakpoint bp: breakpoints) {
        if (bp.get_addr() == regs.rip-1) {
          disable_breakpoint(&bp);
          regs.rip -= 1;

          if (ptrace(PTRACE_SETREGS, proc, NULL, &regs) == -1) {
            std::cout << "Error occured: could not set registers while handeling SIGTRAP" << std::endl;
          }

          single_step();

          enable_breakpoint(&bp);
          update_regs();
          break;
        }
      }
      return 1; 
    }  else {
      return -1;
    }  
  }

  void print_regs() {
    std::cout << "rsp: " << std::hex << regs.rsp << std::endl;
    std::cout << "rax: " << std::hex << regs.rax << std::endl;
    std::cout << "rbp: " << std::hex << regs.rbp << std::endl;
    std::cout << "rip: " << std::hex << regs.rip << std::endl;
  }


  void set_breakpoint(unsigned long addr) {
    for (Breakpoint bp: breakpoints) {
      if (bp.get_addr() == addr) {
        return;
      }
    }
 
    //unsigned long data = ptrace(PTRACE_PEEKDATA, proc, addr, NULL);
    auto data = elf.get_bit_at_addr(addr);

    //uint8_t data_to_save = static_cast<uint8_t>(data & 0xff);

    Breakpoint bp = Breakpoint(addr, data);
    enable_breakpoint(&bp);

    breakpoints.emplace_back(Breakpoint(addr, data)); 
  }

  void delete_breakpoint(uint32_t idx) {
    if (idx > breakpoints.size()) {
      return;
    }

    disable_breakpoint(&(breakpoints[idx]));
    
    breakpoints.erase(breakpoints.begin()+idx); 
  }

  void enable_bp(unsigned int idx) {
    enable_breakpoint(&(breakpoints[idx]));
  }
      
  void disable_bp(unsigned int idx) {
    disable_breakpoint(&(breakpoints[idx]));
  }

  void single_step() {
    if (ptrace(PTRACE_SINGLESTEP, proc, NULL, NULL)) {
      std::cout << "single step failed" << std::endl;
      return;
    }
    waitpid(proc, &status, 0);
    update_regs();
  }

  void list_breakpoints() {
    for (int i = 0; i < breakpoints.size(); i++) {
      std::cout << "brekpoint nr. " << i << " at " << std::hex << breakpoints[i].get_addr() << std::endl;
    }
  }
};


command_t get_cmd() { 
  command_t ret;
  std::string cmd;

  std::getline(std::cin, cmd);
  if (cmd == "") {
    return ret;
  }

  //std::vector<std::string> args;

  std::size_t start = cmd.find_first_not_of(' ', 0);
  std::size_t end = cmd.find(' ', start);

  ret.cmd = cmd.substr(start,  end-start);
    
  while ((start = cmd.find_first_not_of(' ', end)) != std::string::npos) {
    end = cmd.find(' ', start);
    ret.args.emplace_back(cmd.substr(start, end-start));
  }
  
  return ret;
}

int main() {
  // setup

  // run
  Debugger dbg = Debugger("test/test");
  int ret_sig = 1;
 
  while (true) {
    std::cout << "wg> ";
    command_t cmd = get_cmd();

    if (cmd.cmd == "c") {
      ret_sig = dbg.cont();
      if (ret_sig == 0) {
        std::cout << "program exited.." << std::endl;
        //return 0;
      } else if (ret_sig == 1) {
        std::cout << "hit breakpoint.." << std::endl;
      } else if (ret_sig == -1) {
        std::cout << "error occured. Aborting" << std::endl;
        exit(-1);
      }
      //std::cout << ret_sig << std::endl;
    } else if (cmd.cmd == "r") {
      dbg.reset();
    } else if (cmd.cmd == "b") {
      if (!cmd.args.empty()) {
        const char *hex_addr = cmd.args[0].c_str();
        unsigned long bp_addr = strtol(hex_addr, NULL, 16);
             
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
        }
      }
    } else if (cmd.cmd == "d") {
      if (!cmd.args.empty()) {
        uint32_t idx = atoi(cmd.args[0].c_str());
        dbg.delete_breakpoint(idx);
        std::cout << "deleted breakpoint nr.: " << idx << std::endl;
      }
    } else if (cmd.cmd == "quit") {
      break;
    }
  }

}
