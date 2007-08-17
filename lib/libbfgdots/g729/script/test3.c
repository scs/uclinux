#include <stdio.h>

short data[2] = {0,1};

void simgot_init();

int main() {
  simgot_init();
  data[1] += 1;
  printf("data[1] = %d\n", data[1]);
  return 0;
}
