#include <gtest/gtest.h>
#include "../disass.hpp"


#define CODE1 "\x8d\x4c\x24\x04\x83\xe4\xf0\xff\x71\xfc\x55\x89\xe5\x51\x83\xec\x14"
#define CODE2 "\x55\x89\xe5\x83\xec\x08"
#define CODE1_SIZE 17
#define CODE2_SIZE 6


TEST(DisassTest, Addresses_i386) {
  uint64_t code1_expected_addresses[7] = {0x8049176, 0x804917a, 0x804917d, 0x8049180, 0x8049181, 0x8049183, 0x8049184};
  uint64_t code2_expected_addresses[3] = {0x804914d, 0x804914e, 0x8049150};

  auto instructions1 = disassemble_i386(0x8049176, reinterpret_cast<const uint8_t *>(CODE1), CODE1_SIZE);
  auto instructions2 = disassemble_i386(0x804914d, reinterpret_cast<const uint8_t *>(CODE2),  CODE2_SIZE);

  ASSERT_EQ(instructions1.size(), 7);
  ASSERT_EQ(instructions2.size(), 3);
  
  for (size_t i = 0; i < instructions1.size(); i++) {
    std::cout << "Instruction nr. " << i  << " : " << instructions1[i].str() << std::endl;
    ASSERT_EQ(instructions1[i].get_addr(), code1_expected_addresses[i]);
  }

  std::cout << std::endl;
  for (size_t i = 0; i < instructions2.size(); i++) {
    std::cout << "Instruction nr. " << i  << " : " << instructions2[i].str() << std::endl;
    ASSERT_EQ(instructions2[i].get_addr(), code2_expected_addresses[i]);
  }
}

TEST(DisassTest, Sizes_x86_64) {
  uint64_t code1_expected_sizes[7] = {4, 3, 3, 1, 2, 1, 3};
  uint64_t code2_expected_sizes[3] = {1, 2, 3};

  auto instructions1 = disassemble_i386(0x8049176, reinterpret_cast<const uint8_t *>(CODE1), CODE1_SIZE);
  auto instructions2 = disassemble_i386(0x804914d, reinterpret_cast<const uint8_t *>(CODE2),  CODE2_SIZE);

  ASSERT_EQ(instructions1.size(), 7);
  ASSERT_EQ(instructions2.size(), 3);
  
  for (size_t i = 0; i < instructions1.size(); i++) {
    std::cout << "Size of Instruction nr. " << i  << " : " << instructions1[i].get_size() << std::endl;
    ASSERT_EQ(instructions1[i].get_size(), code1_expected_sizes[i]);
  }

  std::cout << std::endl;
  for (size_t i = 0; i < instructions2.size(); i++) {
    std::cout << "Size of Instruction nr. " << i  << " : " << instructions2[i].get_size() << std::endl;
    ASSERT_EQ(instructions2[i].get_size(), code2_expected_sizes[i]);
  }
}

TEST(DisassTest, OpStrings_x86_64) {
  std::string code1_expected_opstr[7] = {"ecx, [esp + 4]", "esp, 0xfffffff0", "dword ptr [ecx - 4]", "ebp", "ebp, esp", "ecx", "esp, 0x14"};
  std::string code2_expected_opstr[3] = {"ebp", "ebp, esp", "esp, 8"};

  auto instructions1 = disassemble_i386(0x8049176, reinterpret_cast<const uint8_t *>(CODE1), CODE1_SIZE);
  auto instructions2 = disassemble_i386(0x804914d, reinterpret_cast<const uint8_t *>(CODE2),  CODE2_SIZE);

  ASSERT_EQ(instructions1.size(), 7);
  ASSERT_EQ(instructions2.size(), 3);
  
  for (size_t i = 0; i < instructions1.size(); i++) {
    std::cout << "Op String of Instruction nr. " << i  << " : " << instructions1[i].get_op_str() << std::endl;
    ASSERT_EQ(instructions1[i].get_op_str(), code1_expected_opstr[i]);
  }

  std::cout << std::endl;
  for (size_t i = 0; i < instructions2.size(); i++) {
    std::cout << "Op String of Instruction nr. " << i  << " : " << instructions2[i].get_op_str() << std::endl;
    ASSERT_EQ(instructions2[i].get_op_str(), code2_expected_opstr[i]);
  }
}

TEST(DisassTest, Mnemonic_x86_64) {
  std::string code1_expected_mnemonics[7] = {"lea", "and", "push", "push", "mov", "push", "sub"};
  std::string code2_expected_mnemonics[3] = {"push", "mov", "sub"};

  auto instructions1 = disassemble_i386(0x8049176, reinterpret_cast<const uint8_t *>(CODE1), CODE1_SIZE);
  auto instructions2 = disassemble_i386(0x804914d, reinterpret_cast<const uint8_t *>(CODE2),  CODE2_SIZE);

  ASSERT_EQ(instructions1.size(), 7);
  ASSERT_EQ(instructions2.size(), 3);
  
  for (size_t i = 0; i < instructions1.size(); i++) {
    std::cout << "Mnemonic of Instruction nr. " << i  << " : " << instructions1[i].get_mnemonic() << std::endl;
    ASSERT_EQ(instructions1[i].get_mnemonic(), code1_expected_mnemonics[i]);
  }

  std::cout << std::endl;
  for (size_t i = 0; i < instructions2.size(); i++) {
    std::cout << "Mnemonic of Instruction nr. " << i  << " : " << instructions2[i].get_mnemonic() << std::endl;
    ASSERT_EQ(instructions2[i].get_mnemonic(), code2_expected_mnemonics[i]);
  }
}




int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

