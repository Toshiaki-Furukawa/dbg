#include <gtest/gtest.h>
#include "../disass.hpp"

#define CODE1 "\x55\x48\x89\xe5\x48\x83\xec\x10\xc7\x45\xfc\x00\x00\x00\x00"
#define CODE2 "\xf3\x0f\x1e\xfa\x80\x3d\x09\x2f\x00\x00\x00\x75\x13"
#define CODE1_SIZE 15
#define CODE2_SIZE 13


TEST(DisassTest, Addresses_x86_64) {
  uint64_t code1_expected_addresses[4] = {0x401136, 0x401137, 0x40113a, 0x40113e};
  uint64_t code2_expected_addresses[3] = {0x1000, 0x1004, 0x100b};

  auto instructions1 = disassemble_x86_64(0x401136, reinterpret_cast<const uint8_t *>(CODE1), CODE1_SIZE);
  auto instructions2 = disassemble_x86_64(0x1000, reinterpret_cast<const uint8_t *>(CODE2),  CODE2_SIZE);

  ASSERT_EQ(instructions1.size(), 4);
  ASSERT_EQ(instructions2.size(), 3);
  
  for (size_t i = 0; i < instructions1.size(); i++) {
    std::cout << "Instruction nr. " << i  << " : " << instructions1[i].str() << std::endl;
    ASSERT_EQ(instructions1[i].address(), code1_expected_addresses[i]);
  }

  std::cout << std::endl;
  for (size_t i = 0; i < instructions2.size(); i++) {
    std::cout << "Instruction nr. " << i  << " : " << instructions2[i].str() << std::endl;
    ASSERT_EQ(instructions2[i].address(), code2_expected_addresses[i]);
  }
}

TEST(DisassTest, Sizes_x86_64) {
  uint64_t code1_expected_sizes[4] = {1, 3, 4, 7};
  uint64_t code2_expected_sizes[3] = {4, 7, 2};

  auto instructions1 = disassemble_x86_64(0x401136, reinterpret_cast<const uint8_t *>(CODE1), CODE1_SIZE);
  auto instructions2 = disassemble_x86_64(0x1000, reinterpret_cast<const uint8_t *>(CODE2),  CODE2_SIZE);

  ASSERT_EQ(instructions1.size(), 4);
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
  std::string code1_expected_opstr[4] = {"rbp", "rbp, rsp", "rsp, 0x10", "dword ptr [rbp - 4], 0"};
  std::string code2_expected_opstr[3] = {"", "byte ptr [rip + 0x2f09], 0", "0x1020"};

  auto instructions1 = disassemble_x86_64(0x401136, reinterpret_cast<const uint8_t *>(CODE1), CODE1_SIZE);
  auto instructions2 = disassemble_x86_64(0x1000, reinterpret_cast<const uint8_t *>(CODE2),  CODE2_SIZE);

  ASSERT_EQ(instructions1.size(), 4);
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
  std::string code1_expected_mnemonics[4] = {"push", "mov", "sub", "mov"};
  std::string code2_expected_mnemonics[3] = {"endbr64", "cmp", "jne"};

  auto instructions1 = disassemble_x86_64(0x401136, reinterpret_cast<const uint8_t *>(CODE1), CODE1_SIZE);
  auto instructions2 = disassemble_x86_64(0x1000, reinterpret_cast<const uint8_t *>(CODE2),  CODE2_SIZE);

  ASSERT_EQ(instructions1.size(), 4);
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

