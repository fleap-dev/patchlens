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

      #ifdef SLOW_FEATURE
        puts("THIS IS SLOW");
      #else

        puts("THIS IS NORMAL");

        #ifndef TEST_FEATURE
          puts("NOT TESTING");
        #else
          puts("TESTING");
        #endif

      #endif
    #endif

  #endif

  return EXIT_SUCCESS;
}
