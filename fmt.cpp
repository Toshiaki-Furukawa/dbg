#include <string>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>

#include "dbgtypes.hpp"
#include "fmt.hpp"

/*
char const* ansi_color_prefix[] = {
  "\033[31m",
  "\033[32m",
  "\033[33m",
  "\033[34m",
  "\033[35m",
  "\033[36m",
  "\033[37m",
  "\033[90m",
  "\033[91m",
  "\033[92m",
  "\033[93m",
  "\033[94m",
  "\033[95m",
  "\033[96m",
  "\033[97m",
  "\033[0m"
};*/

std::string fmt::addr_32(uint64_t addr) {
  std::stringstream ss;

  ss  << "0x" << std::setfill('0') << std::setw(4*2) << std::hex << addr;
  return ss.str();
}

std::string fmt::addr_64(uint64_t addr) {
  std::stringstream ss;

  ss  <<  "0x" << std::setfill('0') << std::setw(8*2) << std::hex << addr;
  return ss.str();
}

std::ostream& fmt::red(std::ostream &o) {return o << "\033[31m"; }

std::ostream& fmt::green(std::ostream &o) {
  return o << "\033[32m";
}
std::ostream& fmt::yellow(std::ostream &o) {
  return o << "\033[33m";
}
std::ostream& fmt::blue(std::ostream &o) {
  return o << "\033[34m";
}
std::ostream& fmt::magenta(std::ostream &o) {
  return o << "\033[35m";
}
std::ostream& fmt::cyan(std::ostream &o) {
  return o << "\033[36m";
}
std::ostream& fmt::white(std::ostream &o) {
  return o << "\033[37m";
}

std::ostream& fmt::endc(std::ostream &o) {
  return o << "\033[0m";
}


/*
int main() {
  std::cout << "hi" << fmt::blue << " this is a test " << fmt::endc << "some" << std::endl;
  std::cout << fmt::addr_32(0x41) << std::endl;
  std::cout << fmt::yellow << fmt::addr_32(0x41) << fmt::endc << std::endl;
  std::cout << fmt::fright(8) << "aaaa" << fmt::fright(8) << "bbbb" << std::endl;
  std::cout << fmt::fright(8) << "aa" << fmt::fright(8) << "bbccd" << std::endl;

}*/
