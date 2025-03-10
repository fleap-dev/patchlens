#include <stdlib.h>
#include <unistd.h>

#define MY_VALUE 15

int main(int argc, char **argv) {

  puts("Hello world!");
#ifdef VERBOSE_FEATURE

  puts("Running on verbose mode!");

#ifdef ANOTHER_FEATURE
  puts("Running on verbose and another!");
#else
  puts("Running on verbose but without ANOTHER");
#endif

#if MY_VALUE > 10
  puts("Running on verbose and MY_VALUE > 10");
#endif

#ifndef FAST_FEATURE
  puts("THIS IS FAST");
#else
  puts("THIS NOT FAST");
#endif

#endif

  return EXIT_SUCCESS;
}
