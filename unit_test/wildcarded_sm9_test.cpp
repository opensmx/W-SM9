#include <iostream>
#include <pbc/pbc.h>
#include <chrono>
#include "schemes/wildcarded_sm9.h"

int main() {
  std::vector<size_t> id_pattern_sizes = {10, 50, 100, 150, 200, 250, 300, 350, 400, 450, 500};
  const size_t iter_times = 1;

  for (auto ips : id_pattern_sizes) {
    id_pattern_size = ips;
    WildcardedSM9 wsm9;
    std::vector<Key *> *keys;
    auto setup_s = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iter_times; ++i) {
      keys = wsm9.SetUp();
    }
    auto setup_e = std::chrono::high_resolution_clock::now();

    std::vector<size_t> id_pattern_lens = {id_pattern_size};
    for (auto id_pattern_len : id_pattern_lens) {
      printf("id_pattern length: %lu\n", id_pattern_len);
      std::vector<std::string> id_pattern = {"0"};

      for (int i = 1; i <= id_pattern_len; ++i) {
        id_pattern.emplace_back(std::to_string(i));
      }

      Key *secret_key;
      auto keygen_s = std::chrono::high_resolution_clock::now();
      for (int i = 0; i < iter_times; ++i) {
        secret_key = wsm9.KeyGen(keys->at(1), keys->at(0), id_pattern);
      }
      auto keygen_e = std::chrono::high_resolution_clock::now();
      element_t m;
      element_init_GT(m, reinterpret_cast<pairing_s *>(wsm9.GetPairing()));
      element_random(m);
//      element_printf("Original Message: %B\n", m);
      Ciphertext *ciphertext;
      auto enc_s = std::chrono::high_resolution_clock::now();
      for (int i = 0; i < iter_times; ++i) {
        ciphertext = wsm9.Encrypt(m, id_pattern, keys->at(1));
      }
      auto enc_e = std::chrono::high_resolution_clock::now();
      auto dec_s = std::chrono::high_resolution_clock::now();
      for (int i = 0; i < iter_times; ++i) {
        element_s *msg = wsm9.Decrypt(ciphertext, secret_key);
      }
      auto dec_e = std::chrono::high_resolution_clock::now();

#define time_cast(a, b) std::chrono::duration_cast<std::chrono::microseconds>(a - b).count()
      printf("setup time: %lf (us).\n", time_cast(setup_e, setup_s) / (double) iter_times);
      printf("keygen time: %lf (us).\n", time_cast(keygen_e, keygen_s) / (double) iter_times);
      printf("encrypt time: %lf (us).\n", time_cast(enc_e, enc_s) / (double) iter_times);
      printf("decrypt time: %lf (us).\n", time_cast(dec_e, dec_s) / (double) iter_times);
      printf("-----------------------------------\n");
#undef time_cast
    }
  }
  return 0;
}
