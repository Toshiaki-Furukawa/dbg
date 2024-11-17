#include <string>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>

#include "dbgtypes.hpp"
#include "fmt.hpp"


std::ostream& fmt::operator<<(std::ostream &o, const fmt::fleft &i) {
  return o << std::left << std::setfill(' ') << std::setw(i.n); 
}

std::ostream& fmt::operator<<(std::ostream &o, const fmt::fright &i) {
  return o <<  std::right <<std::setfill(' ') << std::setw(i.n); 
}

std::string fmt::addr_32(const uint64_t addr) {
  std::stringstream ss;

  ss  << "0x" << std::setfill('0') << std::setw(4*2) << std::hex << addr;
  return ss.str();
}

std::string fmt::addr_64(const uint64_t addr) {
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

/* instructions can be of form 
1. op    0xaddr
2. op    dst, src
3. op    dword ptr [dst], src            can also appear as src, dword ptr dst
3. op    dword ptr [dst + offset], src

*/

std::string fmt::op_intel(std::string op_str) {
  size_t idx = 0;
  std::stringstream ss;
  if (op_str.size() < 3) {
    return op_str; 
  }

  while (idx < op_str.size()) {
    if ((op_str[idx] == 'e' || op_str[idx] == 'r') && op_str[idx + 1] != 'd' && op_str[idx+1] != ' ') {
      ss << fmt::cyan << op_str[idx];
    } else if (op_str[idx] == '0' && op_str[idx+1] == 'x') {
      ss << fmt::yellow << op_str[idx];
    } else if (op_str[idx] == ',' || op_str[idx] == ' ' || op_str[idx] == '[' || op_str[idx] == ']') {
      ss << fmt::endc << op_str[idx];
    } else {
      ss << op_str[idx];
    }
    idx++;
  }

  ss << fmt::endc;
  return ss.str();
}


/*
int main() {
  std::cout << "hi" << fmt::blue << " this is a test " << fmt::endc << "some" << std::endl;
  std::cout << fmt::addr_32(0x41) << std::endl;
  std::cout << fmt::yellow << fmt::addr_32(0x41) << fmt::endc << std::endl;
  std::cout << fmt::fright(8) << "aaaa" << fmt::fright(8) << "bbbb" << std::endl;
  std::cout << fmt::fright(8) << "aa" << fmt::fright(8) << "bbccd" << std::endl;

}*/
