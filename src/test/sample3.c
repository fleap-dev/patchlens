#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static const int GLOBAL_VAR = 5;

int main(int argc, char** argv) {

  puts("Hello world!");
  #ifdef VERBOSE_FEATURE
  puts("Running on verbose mode!");
  #ifdef ANOTHER_FEATURE
  puts("Running on verbose and another!");
  #endif

  printf("Global var value: %d\n", GLOBAL_VAR);

  #endif

  return EXIT_SUCCESS;
}
