#include <unistd.h>
#include <stdio.h>
#include <string>
#include <stdint.h>
#include <iostream>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>


int main() {

  // setup
  pid_t proc = fork();
  int status;
  user_regs_struct regs;

  // run
  if (proc == 0) {
    personality(ADDR_NO_RANDOMIZE);
    ptrace(PTRACE_TRACEME, proc, NULL, NULL);

    //freopen("/dev/null", "w", stdout); 

    execl("test/test", "test/test", NULL, NULL);
  } else {
    while(waitpid(proc, &status, 0)) {
      if (WIFSTOPPED(status) && WSTOPSIG (status) == SIGTRAP) {
        std::cout << "program stopped on SIGTRAP - printing register values:\n";
        ptrace(PTRACE_GETREGS, proc, NULL, &regs);
        std::cout << "rip: " << std::hex << regs.rip << "\n";
        std::cout << "rsp: " << std::hex << regs.rsp << "\n";
        std::cout << "rbp: " << std::hex << regs.rbp << "\n";
        std::cout << "rax: " << std::hex << regs.rax << "\n";
        ptrace(PTRACE_CONT, proc, NULL, NULL);
      } else if (WIFEXITED(status)) {
        std::cout << "program exited - debugger terminating...\n";
        exit(0);
      }
    }
    std::cout << "quit debugging\n";
  }
}
