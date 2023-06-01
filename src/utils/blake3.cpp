//
// Created by fxy on 2023/3/18.
//

#include "utils/blake3.h"
#include <cstdio>
#include <unistd.h>

int main() {
  // Initialize the hasher.
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);

  // Read input bytes from stdin.
  unsigned char buf[65536];

  ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));

  blake3_hasher_update(&hasher, buf, n);

  // Finalize the hash. BLAKE3_OUT_LEN is the default output length, 32 bytes.
  uint8_t output[BLAKE3_OUT_LEN];
  blake3_hasher_finalize(&hasher, output, BLAKE3_OUT_LEN);

  // Print the hash as hexadecimal.
  for (unsigned char i : output) {
    printf("%02x", i);
  }
  printf("\n");
  return 0;
}