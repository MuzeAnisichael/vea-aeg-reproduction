#include <stdio.h>
#include <unistd.h>

void win(void) {
    puts("local toy target reached");
}

void vulnerable(void) {
    char buffer[32];
    puts("input:");
    read(0, buffer, 256);
    puts("done");
}

int main(void) {
    vulnerable();
    return 0;
}

