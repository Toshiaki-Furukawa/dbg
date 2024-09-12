#include <string.h>
#include <cstdint>
#include <iostream>
#include <sstream>
#include "elftypes.hpp"
#include "fmt.hpp"

Section::Section(uint64_t start_addr, uint32_t offset, size_t size, std::string name = "None") 
   : start_addr(start_addr), offset(offset), size(size), name(name) {}

Section::Section(Elf64_Shdr *shdr, std::string name) 
  : start_addr(shdr->sh_addr), offset(shdr->sh_offset), size(shdr->sh_size), name(name) {}

Section::Section(Elf32_Shdr *shdr, std::string name) 
  : start_addr(shdr->sh_addr), offset(shdr->sh_offset), size(shdr->sh_size), name(name) {}


void Section::rebase(uint64_t base_addr) {
  start_addr = offset + base_addr;
}
uint64_t Section::get_offset() const {
  return offset;
}
  
uint64_t Section::get_start() const {
  return start_addr;
}

uint64_t Section::get_size() const {
  return size;
}

std::string Section::str() const {
  /*
    std::cout << "0x" << std::hex << start_addr << "   " 
             << "0x" << std::hex << offset << "   " 
             << "0x" << std::hex << size << "   "  <<  name << std::endl;*/
  std::stringstream ss;
  ss << fmt::addr_64(start_addr) << "  " 
     << fmt::fleft(6) << std::hex << offset << " "
     << fmt::fleft(6) << std::hex << size << name; 
  return ss.str();
}

  // checks if addr is contrained within the section
bool Section::contains(uint64_t addr) const {
  if (addr >= start_addr && addr < start_addr + size) {
    return true;
  } 
  return false;
}

Symbol::Symbol(uint64_t addr, uint32_t offset, uint32_t size, std::string name) : addr(addr), offset(offset), size(size), name(name) {}

/* 
std::string Symbol::str() {
  std::stringstream ss;
  ss << "0x" << std::hex << addr << "  " << size <<  "  " << name; 
  return ss.str();
}*/

void Symbol::rebase(uint64_t base_addr) {
  addr = base_addr + offset;
}


uint64_t Symbol::get_addr() const {
  return addr;
}

uint32_t Symbol::get_offset() const {
  return offset;
}
  
uint32_t Symbol::get_size() const {
  return size;
}

std::string Symbol::str() const {
  //std::cout << "0x" << std::hex << addr << "  " << std::dec << size << "  " << name << std::endl; 
  std::stringstream ss;
  ss << fmt::addr_64(addr) << "  " << fmt::fleft(7) << std::dec << size << name; 
  return ss.str();
}
