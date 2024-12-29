#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

int check_n(char a, int n){
  char key[] = "\nfeebdaed";
  if (n < 0 || n > 8) {
    return 0;
  }
  
  if (key[n] == a) {
    return 1; 
  }
  return 0;
}

int main() {
  char buf[40];
  bool pw_correct;
  memset(buf, 0x0, 40);

  printf("+-------------+\n");
  printf("Simple Crack Me\n");
  printf("+-------------+\n");
  

  int n =  read(0, buf, 40);
  if (n == 9) {
    pw_correct = true;
  }

  for (int i = 0; i < n; i++) {
    if (check_n(buf[i], 8-i) != 1) {
      pw_correct = false;
      break;
    }
  }

  if (pw_correct) {
    printf("yeah! cracked me..\n");
  } else {
    printf("NOPE\n");
  }
}
