#include <stdio.h>
#include "util.h"

void print_byte_array_in_hex(unsigned char *byte_array, size_t length) {
    printf("0x");
    for (size_t i = 0; i < length; i++) {
        printf("%02x", byte_array[i]);
    }
    printf("\n");
}

void rev(char arr[], int n) {
    int l = 0, r = n - 1;
    while (l < r) { char temp = arr[l]; arr[l] = arr[r]; arr[r] = temp; l++; r--; }
}

