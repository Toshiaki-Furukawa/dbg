#include <vector>
#include <string>
#include <sstream>
#include <iostream>
#include <capstone/capstone.h>

#include "disass.hpp"
#include "fmt.hpp"

Instruction::Instruction(cs_insn *insn) {
  //load(insn); // TODO: improve on this code
  size = insn->size;
  addr = insn->address;
  
  for (uint16_t i = 0; i < size; i++) {
    bytes.emplace_back(reinterpret_cast<uint8_t>(insn->bytes[i]));
  }
   
  mnemonic.assign(insn->mnemonic);
  op_str.assign(insn->op_str);   
}

/* 
void Instruction::load(cs_insn *insn) {
  size = insn->size;
  addr = insn->address;
  
  for (uint16_t i = 0; i < size; i++) {
    bytes.emplace_back(reinterpret_cast<uint8_t>(insn->bytes[i]));
  }
   
  mnemonic.assign(insn->mnemonic);
  op_str.assign(insn->op_str);   
}*/

void Instruction::set_prefix(std::string const s) {
  this->prefix.assign(s);
}

void Instruction::set_suffix(std::string suffix) {
  this->suffix.assign(suffix);
}

uint64_t Instruction::get_addr() const {
  return addr;
}


uint16_t Instruction::get_size() const {
  return size;
}

  
std::string Instruction::get_mnemonic() const {
  return mnemonic;
}

std::string Instruction::get_op_str() const {
  return op_str;
}

std::string Instruction::str() const {
  std::stringstream ss;

  if (addr < 0xffffffff) {
  //std::cout << "aaa" << this->prefix << "bbbb" << std::endl;
    ss << prefix  << fmt::addr_32(addr) << "       "  << fmt::fleft(7) << mnemonic <<  op_str << fmt::fright(20) << suffix;
  } else {
    ss << prefix  << fmt::addr_64(addr) << "       "  << fmt::fleft(7) << mnemonic <<  op_str << fmt::fright(20) << suffix;
  }
  return ss.str();
}

std::vector<Instruction> disassemble(cs_arch arch, cs_mode mode, uint64_t addr, const uint8_t *code, size_t code_size) {
  csh handle;
  cs_insn *insn;
  std::vector<Instruction> instructions;

  if (cs_open(arch, mode, &handle) != CS_ERR_OK)
    return instructions; 

  cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

  auto count = cs_disasm(handle, code, code_size, addr, 0, &insn);
  if (count > 0) {
    for (size_t i = 0; i < count; i++) {
      Instruction instr(&insn[i]);
      instructions.emplace_back(instr);
    }
    cs_free(insn, count);
  } else {
    return instructions;
  }

  cs_close(&handle);
  return instructions;

}

std::vector<Instruction> disassemble_x86_64(uint64_t addr, const uint8_t *code, size_t code_size) {
  auto ret = disassemble(CS_ARCH_X86, CS_MODE_64, addr, code, code_size);
  
  if (ret.size() == 0) {
    std::cout << "could not disassemble" << std::endl;
    return ret;
  }
  return ret;
}

std::vector<Instruction> disassemble_i386(uint64_t addr, const uint8_t *code, size_t code_size) {
  auto ret = disassemble(CS_ARCH_X86, CS_MODE_32, addr, code, code_size);

  if (ret.size() == 0) {
    std::cout << "could not disassemble" << std::endl;
    return ret;
  }
  return ret;
}
 
/*
int main() {
  const char *code = "\x55\x89\xe5\x51\x83\xec\x14\xc7\x45\xf4\x00\x00\x00\x00";
  size_t code_size = 14;

  auto instructions = disassemble_i386(0x1000, reinterpret_cast<const uint8_t*>(&(code[0])), code_size);

  for (auto instr : instructions) {
    std::cout << instr.str() << std::endl; 
  }
}*/
