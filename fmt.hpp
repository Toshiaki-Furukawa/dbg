#pragma once
#include <string>
#include <cstdint>

namespace fmt {
  /*
  typedef enum color_t {
    red = 0,
    green,
    yellow,
    blue,
    magenta,
    cyan,
    white,
    bright_black,
    bright_red,
    bright_green,
    bright_yellow,
    bright_blue,
    bright_magenta,
    bright_cyan,
    bright_white,
    reset, 
  } color_t;*/

  class fleft {
  public:
    explicit constexpr fleft(uint32_t n) : n(n) {} 

  private:
    uint32_t n;
  
    friend std::ostream& operator<<(std::ostream &o, const fleft &i) {
      return o << std::left << std::setfill(' ') << std::setw(i.n); 
    }
  };

  class fright {
  public:
    explicit constexpr fright(uint32_t n): n(n) {}

  private:
    uint32_t n;
  
    friend std::ostream& operator<<(std::ostream &o, const fright &i) {
     return o <<  std::right <<std::setfill(' ') << std::setw(i.n); 
    }
  };

  std::string addr_32(uint64_t addr);

  std::string addr_64(uint64_t addr);

  std::ostream& red(std::ostream &o);

  std::ostream& green(std::ostream &o);

  std::ostream& yellow(std::ostream &o);

  std::ostream& blue(std::ostream &o);

  std::ostream& magenta(std::ostream &o);

  std::ostream& cyan(std::ostream &o);

  std::ostream& white(std::ostream &o);

  std::ostream& endc(std::ostream &o);
}
