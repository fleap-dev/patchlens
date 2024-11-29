#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char** argv) {

  puts("Hello world!");
  #ifdef VERBOSE_FEATURE
  puts("Running on verbose mode!");
  #ifdef ANOTHER_FEATURE
  puts("Running on verbose and another!");
  puts("This will only affect the variant with these two features");
  #endif
  #endif

  return EXIT_SUCCESS;
}
