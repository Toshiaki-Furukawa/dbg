#include <string.h>
#include <cstdint>
#include <iostream>
#include <sstream>
#include "elftypes.hpp"

Section::Section(uint64_t start_addr, uint64_t offset, size_t size, std::string name = "None") 
   : start_addr(start_addr), offset(offset), size(size), name(name) {}

Section::Section(Elf64_Shdr *shdr, std::string name) 
  : start_addr(shdr->sh_addr), offset(shdr->sh_offset), size(shdr->sh_size), name(name) {}

Section::Section(Elf32_Shdr *shdr, std::string name) 
  : start_addr(shdr->sh_addr), offset(shdr->sh_offset), size(shdr->sh_size), name(name) {}

uint64_t Section::get_offset() {
  return offset;
}
  
uint64_t Section::get_start() {
  return start_addr;
}

uint64_t Section::get_size() {
  return size;
}

void Section::print_section() {
    std::cout << "0x" << std::hex << start_addr << "   " 
             << "0x" << std::hex << offset << "   " 
             << "0x" << std::hex << size << "   "  <<  name << std::endl;
}

  // checks if addr is contrained within the section
bool Section::contains(uint64_t addr) {
  if (addr >= start_addr && addr < start_addr + size) {
    return true;
  } 
  return false;
}

Symbol::Symbol(uint64_t addr, uint32_t size, std::string name) : addr(addr), size(size), name(name) {}
 
std::string Symbol::str() {
  std::stringstream ss;
  ss << "0x" << std::hex << addr << "  " << size <<  "  " << name; 
  return ss.str();
}

uint64_t Symbol::get_addr() {
  return addr;
}
  
uint32_t Symbol::get_size() {
  return size;
}

void Symbol::print_symbol() {
  std::cout << "0x" << std::hex << addr << "  " << std::dec << size << "  " << name << std::endl; 
}
