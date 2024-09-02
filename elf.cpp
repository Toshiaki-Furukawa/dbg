#include <elf.h>
#include <inttypes.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <fstream>
#include <vector>
#include <iostream>
#include "disass.cpp"

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
    if (addr > start_addr && addr < start_addr + size) {
      return true;
    } 
    return false;
  }

};

class ELF {
private:
  const char* filename;
  char *content; 
  int machine;            // stores machine or -1 if the file could not be read
  size_t content_size;
  std::vector<Section> sections;
  // security features
  bool is_pie; 
  
 
  void read_sections_x86_64() {
    auto elf_header = reinterpret_cast<Elf64_Ehdr*>(content);

    if (elf_header->e_type == ET_DYN) {
      is_pie = true;
    }
    // optional to get name of section
    auto shdr_string = reinterpret_cast<Elf64_Shdr*>(&content[elf_header->e_shoff + (elf_header->e_shstrndx * elf_header->e_shentsize)]);

    for (int i = 0; i < elf_header->e_shnum; i++) {
      // compute offset for section table entry in file
      uint64_t sht_e_offset = elf_header->e_shoff + (i*elf_header->e_shentsize);

      // read section table 
      auto *shdr = reinterpret_cast<Elf64_Shdr*>(&content[sht_e_offset]);
      sections.emplace_back(Section(static_cast<uint64_t>(shdr->sh_addr), 
                                    static_cast<uint64_t>(shdr->sh_offset), 
                                    static_cast<uint64_t>(shdr->sh_size),
                                    reinterpret_cast<char *>((&content[shdr_string->sh_offset + shdr->sh_name]))));
    }
  }

  void read_sections_i386() {
    auto elf_header = reinterpret_cast<Elf32_Ehdr*>(content);

    if (elf_header->e_type == ET_DYN) {
      is_pie = true;
    }
    // optional to get name of section
    auto shdr_string = reinterpret_cast<Elf32_Shdr*>(&content[elf_header->e_shoff + (elf_header->e_shstrndx * elf_header->e_shentsize)]);

    for (int i = 0; i < elf_header->e_shnum; i++) {
      // compute offset for section table entry in file
      uint32_t sht_e_offset = elf_header->e_shoff + (i*elf_header->e_shentsize);

      // read section table entry 
      auto *shdr = reinterpret_cast<Elf32_Shdr*>(&content[sht_e_offset]);
      sections.emplace_back(Section(static_cast<uint32_t>(shdr->sh_addr), 
                                    static_cast<uint32_t>(shdr->sh_offset), 
                                    static_cast<uint32_t>(shdr->sh_size),
                                    reinterpret_cast<char *>((&content[shdr_string->sh_offset + shdr->sh_name]))));
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

  std::vector<Instruction> disassemble_words(uint64_t addr, size_t n) {
    //TODO:  check size valid 
    std::vector<Instruction> instructions;

    auto idx = get_idx_from_addr(addr);

    if (idx == -1) {
      std::cout << "Not a valid address" << std::endl;
      return instructions;
    }

    size_t size = n*4;
  

    if (size + idx >= content_size) {
      std::cout << "Too many words." << std::endl;
    }
  
    switch (machine) {
      case EM_X86_64:
        instructions = disassemble_x86_64(addr, reinterpret_cast<const uint8_t*>(&(content[idx])), size);
        break;
      case EM_386:
        instructions = disassemble_i386(addr, reinterpret_cast<const uint8_t*>(&(content[idx])),  size);
        break;
      default:
        std::cout << "Architecture not supported";
        return instructions;
    }
    return instructions; 
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
};

/*
int main() {
  ELF elf("test/test_64");
  
  auto instructions = elf.disassemble_words(0x401137, 9);
  for (auto instr : instructions) {
    std::cout << instr.str() << std::endl;
  }
}*/

