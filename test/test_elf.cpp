#include <gtest/gtest.h>
#include "../elftypes.hpp"
#include "../elf.hpp"

TEST(ElfTest, ConstructorValidFile) {
  const char* filename1 = "test_targets/test_64";
  const char* filename2 = "test_targets/test_32";
  
  ELF elf1(filename1);
  ELF elf2(filename2);

  ASSERT_EQ(elf1.get_machine(), EM_X86_64);
  ASSERT_EQ(elf1.get_filename(), filename1);

  ASSERT_EQ(elf2.get_machine(), EM_386);
  ASSERT_EQ(elf2.get_filename(), filename2);
}

TEST(ElfTest, ConstructorNotValid) {
  const char* filename1 = "doesnotexit";
  const char* filename2 = "test_targets/not_elf";
  const char* filename3 = "test_targets/not_elf_long";

  ELF elf1(filename1);
  ELF elf2(filename2);
  ELF elf3(filename3);

  ASSERT_EQ(elf1.get_machine(), -1);
  ASSERT_EQ(elf1.get_filename(), filename1);

  ASSERT_EQ(elf2.get_machine(), -1);
  ASSERT_EQ(elf2.get_filename(), filename2);

  ASSERT_EQ(elf3.get_machine(), -1);
  ASSERT_EQ(elf2.get_filename(), filename2);
}


TEST(ElfTest, GetByteAddr) {
  const char *filename32 = "test_targets/test_32";
  const char *filename64 = "test_targets/test_64";

  ELF elf32(filename32);
  elf32.rebase(0x8048000);
  ELF elf64(filename64);
  elf64.rebase(0x400000);

  ASSERT_EQ(elf32.get_byte_at_addr(0x8049180), '\x55');
  ASSERT_EQ(elf32.get_byte_at_addr(0x8049181), '\x89');
  ASSERT_EQ(elf32.get_byte_at_addr(0x8049182), '\xe5');
  ASSERT_EQ(elf32.get_byte_at_addr(0x8049183), '\x51');


  ASSERT_EQ(elf64.get_byte_at_addr(0x40114c), '\xbf');
  ASSERT_EQ(elf64.get_byte_at_addr(0x40114c+1), '\x10');
  ASSERT_EQ(elf64.get_byte_at_addr(0x40114c+2), '\x20');
  ASSERT_EQ(elf64.get_byte_at_addr(0x40114c+3), '\x40');
  //ASSERT_EQ(elf64.get_byte_at_addr(0x40114c+4), 0x00);
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

