#pragma once
//#include "elftypes.hpp"
#include <map>
#include <string>
#include <cstdint>
#include <elf.h>
#include <unordered_map>
#include "elftypes.hpp"
#include "disass.hpp"


class ELF {
private:
  const char* filename;
  char *content; 
  size_t content_size;
  int machine;            // stores machine or -1 if the file could not be read
  uint64_t base;

  //std::vector<Section> sections;
  std::unordered_map<std::string, Section> sections;
  std::unordered_map<std::string, Symbol> symtab;
  // security features
  bool is_pie; 
 
  // RESDING SYMTABLE 
  template<typename T>
  void read_symtab(uint32_t sh_offset, uint32_t sh_size, uint32_t strtab_offset);

  void read_symtab_i386(uint32_t sh_offset, uint32_t sh_size, uint32_t strtab_offset);

  void read_symtab_x86_64(uint32_t sh_offset, uint32_t sh_size, uint32_t strtab_offset);

  // READ SECTONS 
  template<typename Elf_Eh, typename Elf_Sh>
  void get_sections();

  void read_sections_x86_64();

  void read_sections_i386();
 
public:
  ELF(const char* filename);

  ~ELF();
 
  void rebase(uint64_t base_addr);
 
  int get_machine() const;
  
  const char* get_filename() const;
  
  bool pie() const;



  char get_byte_at_offset(uint32_t offset) const;

  char get_byte_at_addr(uint64_t addr) const;

  uint8_t *get_n_bytes_at_addr(uint64_t addr, uint32_t n);

  uint8_t *get_n_bytes_at_offset(uint64_t addr, uint32_t n);



  uint32_t get_symbol_offset(std::string symbol) const;

  uint64_t get_symbol_addr(std::string symbol) const;

  uint32_t get_symbol_size(std::string symbol) const;



  // DEBUG FUNCTIONS
  void print_filename() const;

  void print_sections() const;
   
  void print_symtab() const;
};

