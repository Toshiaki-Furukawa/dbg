#include <gtest/gtest.h>
#include "../dbg.hpp"

TEST(DebuggerTest, TestCont) {
  const char* filename_32 = "test_targets/test_32";
  const char* filename_64 = "test_targets/test_64";
  
  Debugger dbg_32(filename_32);
  Debugger dbg_64(filename_64);

  dbg_32.set_breakpoint(0x8049195);
  dbg_32.set_breakpoint(0x80491ab);
  dbg_32.set_breakpoint(0x80491c3);
 
  dbg_64.set_breakpoint(0x40113a);
  dbg_64.set_breakpoint(0x40115e);
  dbg_64.set_breakpoint(0x40117a);

  dbg_32.cont();
  ASSERT_EQ(dbg_32.get_rip(), 0x8049198);
  dbg_32.cont();
  ASSERT_EQ(dbg_32.get_rip(), 0x80491ad);
  dbg_32.cont();
  ASSERT_EQ(dbg_32.get_rip(), 0x80491c8);



  dbg_64.cont();
  ASSERT_EQ(dbg_64.get_rip(), 0x40113e);
  dbg_64.cont();
  ASSERT_EQ(dbg_64.get_rip(), 0x401161);
  dbg_64.cont();
  ASSERT_EQ(dbg_64.get_rip(), 0x40117b);
}

TEST(DebuggerTest, SingleStep) {
  const char* filename_32 = "test_targets/test_32";
  const char* filename_64 = "test_targets/test_64";
  
  Debugger dbg_32(filename_32);
  Debugger dbg_64(filename_64);

  dbg_32.set_breakpoint(0x80491a2);
  dbg_64.set_breakpoint(0x40113a);
  
  dbg_32.cont();
  ASSERT_EQ(dbg_32.get_rip(), 0x80491a5);
  dbg_32.single_step();
  ASSERT_EQ(dbg_32.get_rip(), 0x80491a8);
  dbg_32.single_step();
  ASSERT_EQ(dbg_32.get_rip(), 0x80491ab);
  dbg_32.single_step();
  ASSERT_EQ(dbg_32.get_rip(), 0x80491ad);

  dbg_64.cont();
  ASSERT_EQ(dbg_64.get_rip(), 0x40113e);
  dbg_64.single_step();
  ASSERT_EQ(dbg_64.get_rip(), 0x401145);
  dbg_64.single_step();
  ASSERT_EQ(dbg_64.get_rip(), 0x40114c);
  dbg_64.single_step();
  ASSERT_EQ(dbg_64.get_rip(), 0x401151);
  dbg_64.single_step();
   
}


int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
