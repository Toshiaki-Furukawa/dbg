#include <elf.h>
//#include <inttypes.h>
//#include <stdio.h>
//#include <stddef.h>
//#include <stdlib.h>
#include <fstream>
#include <vector>
#include <iostream>
#include "disass.cpp"
#include <map>

class Section {
private:
  uint64_t start_addr;
  uint64_t offset;
  uint64_t size;
  const std::string name;

public:
  Section(uint64_t start_addr, uint64_t offset, size_t size, std::string name = "None") 
   : start_addr(start_addr), offset(offset), size(size), name(name) {}

  uint64_t get_offset() {
    return offset;
  }
  
  uint64_t get_start() {
    return start_addr;
  }

  uint64_t get_size() {
    return size;
  }

  void print_section() {
      std::cout << "0x" << std::hex << start_addr << "   " 
               << "0x" << std::hex << offset << "   " 
               << "0x" << std::hex << size << "   "  <<  name << std::endl;
  }

  // checks if addr is contrained within the section
  bool contains(uint64_t addr) {
    if (addr >= start_addr && addr < start_addr + size) {
      return true;
    } 
    return false;
  }
};

class Symbol {
private:
  uint64_t addr;
  uint32_t size;
  std::string name;

public:
  Symbol(uint64_t addr, uint32_t size, std::string name) : addr(addr), size(size), name(name) {}
 
  std::string str() {
    std::stringstream ss;
    ss << "0x" << std::hex << addr << "  " << size <<  "  " << name; 
    return ss.str();
  }

  uint64_t get_addr() {
    return addr;
  }
  
  uint32_t get_size() {
    return size;
  }

  void print_symbol() {
    std::cout << "0x" << std::hex << addr << "  " << std::dec << size << "  " << name << std::endl; 
  }
};

class ELF {
private:
  const char* filename;
  char *content; 
  int machine;            // stores machine or -1 if the file could not be read
  size_t content_size;
  std::vector<Section> sections;
  std::map<std::string, Symbol> symtab;
  // security features
  bool is_pie; 
 
  // RESDING SYMTABLE 
  void read_symtab_i386(uint32_t strtab_offset, Elf32_Shdr *shdr) {
    auto sym_table = reinterpret_cast<Elf32_Sym*>(&content[shdr->sh_offset]);
    auto sym_count = static_cast<uint32_t>(shdr->sh_size)/sizeof(Elf32_Sym);

    for (uint32_t i = 0; i < sym_count; i++ ) {
      auto name = static_cast<std::string>(&(content[strtab_offset + sym_table[i].st_name]));

      symtab.emplace(std::pair(name, Symbol(static_cast<uint64_t>(sym_table[i].st_value), static_cast<uint32_t>(sym_table[i].st_size), name)));
    }
  } 

  void read_symtab_x86_64(uint32_t strtab_offset, Elf64_Shdr *shdr) {
    auto sym_table = reinterpret_cast<Elf64_Sym*>(&content[shdr->sh_offset]);
    auto sym_count = static_cast<uint32_t>(shdr->sh_size)/sizeof(Elf64_Sym);

    for (uint32_t i = 0; i < sym_count; i++ ) {
      auto name = reinterpret_cast<const char *>(&(content[strtab_offset + sym_table[i].st_name]));

      symtab.emplace(std::pair(name, Symbol(static_cast<uint64_t>(sym_table[i].st_value), static_cast<uint32_t>(sym_table[i].st_size), name)));
    }
  }

  // READ SECTONS 
  void read_sections_x86_64() {
    auto elf_header = reinterpret_cast<Elf64_Ehdr*>(content);

    if (elf_header->e_type == ET_DYN) {
      is_pie = true;
    }

    Elf64_Shdr *sh_symtab = NULL;
    Elf64_Shdr *sh_dynsym = NULL;
    Elf64_Shdr *sh_strtab = NULL;
    Elf64_Shdr *sh_dynstr = NULL;

    // optional to get name of section
    auto shdr_string = reinterpret_cast<Elf64_Shdr*>(&content[elf_header->e_shoff + (elf_header->e_shstrndx * elf_header->e_shentsize)]);

    for (int i = 0; i < elf_header->e_shnum; i++) {
      // compute offset for section table entry in file
      uint64_t sht_e_offset = elf_header->e_shoff + (i*elf_header->e_shentsize);

      // read section table 
      auto *shdr = reinterpret_cast<Elf64_Shdr*>(&content[sht_e_offset]);

      auto name = static_cast<std::string>((&content[shdr_string->sh_offset + shdr->sh_name]));

      // check if we found symbol table
      switch (shdr->sh_type) {
        case SHT_SYMTAB:
          sh_symtab = shdr;
          break;
        case SHT_DYNSYM:
          sh_dynsym = shdr;
          break;
        case SHT_STRTAB:
          // TODO: identify right symtab
          if (name == ".strtab") {
            sh_strtab = shdr;
          } else if (name == ".dynstr") {
            sh_dynstr = shdr;
          }
          break;
       default:
          break;
      }

      sections.emplace_back(Section(static_cast<uint64_t>(shdr->sh_addr), 
                                    static_cast<uint64_t>(shdr->sh_offset), 
                                    static_cast<uint64_t>(shdr->sh_size),
                                    reinterpret_cast<char *>((&content[shdr_string->sh_offset + shdr->sh_name]))));

    }
    
    if (sh_symtab != NULL && sh_strtab != NULL) {
      read_symtab_x86_64(sh_strtab->sh_offset, sh_symtab);
    } else if (sh_dynsym != NULL && sh_dynstr != NULL) {
      read_symtab_x86_64(sh_dynstr->sh_offset, sh_dynsym);
    }
  }


  void read_sections_i386() {
    auto elf_header = reinterpret_cast<Elf32_Ehdr*>(content);

    if (elf_header->e_type == ET_DYN) {
      is_pie = true;
    }

    // Data for symbol table
    Elf32_Shdr *sh_symtab = NULL;
    Elf32_Shdr *sh_dynsym = NULL;
    Elf32_Shdr *sh_strtab = NULL;
    Elf32_Shdr *sh_dynstr = NULL;

    // optional to get name of section
    auto shdr_string = reinterpret_cast<Elf32_Shdr*>(&content[elf_header->e_shoff + (elf_header->e_shstrndx * elf_header->e_shentsize)]);

    for (int i = 0; i < elf_header->e_shnum; i++) {
      // compute offset for section table entry in file
      uint32_t sht_e_offset = elf_header->e_shoff + (i*elf_header->e_shentsize);

      // read section table entry 
      auto *shdr = reinterpret_cast<Elf32_Shdr*>(&content[sht_e_offset]);

      auto name = static_cast<std::string>((&content[shdr_string->sh_offset + shdr->sh_name]));

      // check if we found symbol table
      switch (shdr->sh_type) {
        case SHT_SYMTAB:
          sh_symtab = shdr;
          break;
        case SHT_DYNSYM:
          sh_dynsym = shdr;
          break;
        case SHT_STRTAB:
          // TODO: identify right symtab
          if (name == ".strtab") {
            sh_strtab = shdr;
          } else if (name == ".dynstr") {
            sh_dynstr = shdr;
          }
          break;
       default:
          break;
      }

      sections.emplace_back(Section(static_cast<uint32_t>(shdr->sh_addr), 
                                    static_cast<uint32_t>(shdr->sh_offset), 
                                    static_cast<uint32_t>(shdr->sh_size),
                                    reinterpret_cast<char *>((&content[shdr_string->sh_offset + shdr->sh_name]))));
    }

    if (sh_symtab != NULL && sh_strtab != NULL) {
      read_symtab_i386(sh_strtab->sh_offset, sh_symtab);
    } else if (sh_dynsym != NULL && sh_dynstr != NULL) {
      read_symtab_i386(sh_dynstr->sh_offset, sh_dynsym);
    }

  }
 
public:
  ELF(const char* filename): filename(filename){
    content = NULL;
    machine = -1;
    is_pie = false;
    
    std::ifstream elf_file(filename, std::ios::binary | std::ios::ate);
    
    if (!elf_file.is_open()) {
      std::cout << "file does not exist" << std::endl;
      return;
    }
    

 
    elf_file.seekg(0, std::ios::end); 
    content_size = elf_file.tellg();
    elf_file.seekg(0, std::ios::beg);
   
    // rough check if to make sure file is large enough to be ELF 
    if (content_size < 16+3) {
      std::cout << "size to small" << std::endl;
      return;
    } 
 
  
    content = new char[content_size];
 
    std::cout << content_size << std::endl; 
    if (!elf_file.read(content, content_size)) {
      std::cout << "something went wrong reading file" << std::endl;
      return;
    }
    

 
    // checking magic bytes 
    if (!(content[0] == 0x7f &&
          content[1] == 'E' &&
          content[2] == 'L' &&
          content[3] == 'F')) {
      std::cout << "File is not ELF" << std::endl;
      return;     
    }

    // get the machien architecture
    machine = static_cast<uint16_t>(content[16+2]);

    // read sections based on architecture
    switch (machine) {
      case EM_X86_64:
        std::cout << "64 bit ELF" << std::endl; 
        read_sections_x86_64();
        break;
      case EM_386:
        std::cout << "32 bit ELF" << std::endl; 
        read_sections_i386();
        break;
      default:
        std::cout << "Format not supported";
        return;
    }
  }

  ~ELF() {
    if (content != NULL) {
      delete[] content;
    }
  }
  
  int get_machine() {
    return machine;
  }
  
  const char* get_filename() {
    return filename;
  }
  
  std::vector<Instruction> disassemble_bytes(uint64_t addr, size_t n) {
    std::vector<Instruction> instructions;

    auto idx = get_idx_from_addr(addr);

    if (idx == -1) {
      std::cout << "Not a valid address" << std::endl;
      return instructions;
    }

    if (n + idx >= content_size) {
      std::cout << "Range is to big." << std::endl;
    }
  
    switch (machine) {
      case EM_X86_64:
        instructions = disassemble_x86_64(addr, reinterpret_cast<const uint8_t*>(&(content[idx])), n);
        break;
      case EM_386:
        instructions = disassemble_i386(addr, reinterpret_cast<const uint8_t*>(&(content[idx])),  n);
        break;
      default:
        std::cout << "Architecture not supported";
        return instructions;
    }
    return instructions; 
  }

  std::vector<Instruction> disassemble_words(uint64_t addr, size_t n) {
    return disassemble_bytes(addr, n*4);
  }


  int get_idx_from_addr(uint64_t addr) {
    // find correct section
    for (auto s: sections) {
      if (s.contains(addr)) {
        return addr - s.get_start() + s.get_offset();
      }
    }
    return -1;
  }

  char get_bit_at_addr(uint64_t addr) {
    auto idx =  get_idx_from_addr(addr);
    if (idx < 0) {
      std::cout << "Not a valid address";
      return -1;
    }

    return content[idx];
  }

  uint64_t get_symbol_addr(std::string symbol) {
    auto it = symtab.find(symbol);
    
    if (it == symtab.end()) {
      return 0;
    }
    return it->second.get_addr();
  }

  uint32_t get_symbol_size(std::string symbol) {
    auto it = symtab.find(symbol);
    if (it == symtab.end()) {
      return 0;
    }
    return it->second.get_size();
  }

  bool pie() {
    return is_pie;
  }

  // DEBUG FUNCTIONS
  void print_filename() {
    std::cout << filename << std::endl;
  }

  void print_sections() {
    for (auto s: sections) {
      s.print_section();
    }
  }
   
  void print_symtab() {
    for (auto& sym_entry: symtab) {
      //std::cout << sym_entry.second.str() << std::endl;
      sym_entry.second.print_symbol();
    }
  }
};
