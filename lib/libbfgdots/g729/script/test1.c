#include <stdio.h>

short data[2] = {0,1};

int main() {
  data[1] += 1;
  printf("data[1] = %d\n", data[1]);
  return 0;
}
