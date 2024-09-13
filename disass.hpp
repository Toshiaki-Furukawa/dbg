#pragma once
#include <capstone/capstone.h>

class Instruction {
private: 
  uint16_t size;
  uint64_t addr;
  std::vector<uint8_t> bytes;
  std::string mnemonic;
  std::string op_str;
  std::string suffix;

public:
  std::string prefix;

  Instruction(cs_insn *insn);
  
  //void load(cs_insn *insn) ;

  void set_prefix(std::string prefix);

  void set_suffix(std::string suffix);

  uint64_t get_addr() const;

  uint16_t get_size() const;

  
  std::string get_mnemonic() const;

  std::string get_op_str() const;

  std::string str() const;
};


std::vector<Instruction> disassemble(cs_arch arch, cs_mode mode, uint64_t addr, const uint8_t *code, size_t code_size);

std::vector<Instruction> disassemble_x86_64(uint64_t addr, const uint8_t *code, size_t code_size);

std::vector<Instruction> disassemble_i386(uint64_t addr, const uint8_t *code, size_t code_size);
