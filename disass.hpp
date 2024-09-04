#pragma once
#include <capstone/capstone.h>

class Instruction {
private: 
  uint16_t size;
  uint64_t addr;
  std::vector<uint8_t> bytes;
  std::string mnemonic;
  std::string op_str;

public:
  Instruction(cs_insn *insn);
  
  void load(cs_insn *insn);

  uint64_t address();

  uint16_t get_size();

  
  std::string get_mnemonic();

  std::string get_op_str();

  std::string str();
};


std::vector<Instruction> disassemble(cs_arch arch, cs_mode mode, uint64_t addr, const uint8_t *code, size_t code_size);

std::vector<Instruction> disassemble_x86_64(uint64_t addr, const uint8_t *code, size_t code_size);

std::vector<Instruction> disassemble_i386(uint64_t addr, const uint8_t *code, size_t code_size);
