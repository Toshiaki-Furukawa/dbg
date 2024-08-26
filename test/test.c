#include <stdio.h>

int main() {
  int x = 0;
  int y = 8;
  int z;
  printf("hello\n");
  z = x + y;
  __asm__("int3");
  printf("%d\n", z);
  return 0;
}
