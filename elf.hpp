#pragma once
//#include "elftypes.hpp"
#include <elf.h>
#include "elftypes.hpp"
#include "disass.hpp"

class ELF {
private:
  const char* filename;
  char *content; 
  int machine;            // stores machine or -1 if the file could not be read
  size_t content_size;
  //std::vector<Section> sections;
  std::map<std::string, Section> sections;
  std::map<std::string, Symbol> symtab;
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
  
  int get_machine();
  
  const char* get_filename();
  
  bool pie();

  int get_idx_from_addr(uint64_t addr);

  char get_bit_at_addr(uint64_t addr);

  uint64_t get_symbol_addr(std::string symbol);

  uint32_t get_symbol_size(std::string symbol);


  std::vector<Instruction> disassemble_bytes(uint64_t addr, size_t n);

  std::vector<Instruction> disassemble_words(uint64_t addr, size_t n);

  // DEBUG FUNCTIONS
  void print_filename();

  void print_sections();
   
  void print_symtab();
};

