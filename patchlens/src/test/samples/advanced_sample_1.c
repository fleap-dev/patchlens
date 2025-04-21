#include <stdio.h>

#define FEAT_A

#ifdef FEAT_A
#define BUFFER_SIZE 1024
#else
#define BUFFER_SIZE 2048
#endif

int main() {
    #ifdef BUFFER_SIZE
        puts("Playing with large buffer size");
    #else
        puts("Playing with normal buffer size");
    #endif
}
