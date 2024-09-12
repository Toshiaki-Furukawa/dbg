#pragma once
#include <string>
#include <cstdint>
#include <iomanip>

namespace fmt {

  class fleft {
  public:
    constexpr fleft(uint32_t n) : n(n) {} 

  private:
    uint32_t n;
  
    friend std::ostream& operator<<(std::ostream &o, const fleft &i);
  };

  class fright {
  public:
    constexpr fright(uint32_t n): n(n) {}

  private:
    uint32_t n;
  
    friend std::ostream& operator<<(std::ostream &o, const fright &i);
  };

  std::ostream& operator<<(std::ostream &o, const fright &i);
  
  std::ostream& operator<<(std::ostream &o, const fleft &i);

  std::string addr_32(const uint64_t addr);

  std::string addr_64(const uint64_t addr);

  std::ostream& red(std::ostream &o);

  std::ostream& green(std::ostream &o);

  std::ostream& yellow(std::ostream &o);

  std::ostream& blue(std::ostream &o);

  std::ostream& magenta(std::ostream &o);

  std::ostream& cyan(std::ostream &o);

  std::ostream& white(std::ostream &o);

  std::ostream& endc(std::ostream &o);
}
