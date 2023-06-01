//
// Created by fxy on 2023/3/16.
//

#include <cassert>
#include <cstring>
#include <omp.h>
#include "schemes/wildcarded_sm9.h"
#include "curve/params.h"
#include "utils/blake3.h"

WildcardedSM9::WildcardedSM9() {
  pbc_param_t par;
  CurveParams curves;
  pbc_param_init_set_str(par, CurveParams::f_param.c_str());
  pairing_init_pbc_param(pairing_, par);
}

std::vector<Key *> *WildcardedSM9::SetUp() {
  Key *master_key = new Key(Key::MASTER);
  Key *public_parameters = new Key(Key::PUBLIC);

  element_t g, g1, g2;
  element_init_G1(g, pairing_);
  element_init_G1(g1, pairing_);
  element_init_G2(g2, pairing_);
  element_random(g);
  element_random(g2);
  public_parameters->InsertComponent("g", "G1", g);
  public_parameters->InsertComponent("g2", "G2", g2);

  element_t g_tilde_i;
  element_init_G2(g_tilde_i, pairing_);

  for (int i = 1; i <= id_pattern_size; ++i) {
    element_random(g_tilde_i);
    public_parameters->InsertComponent("g_hat_" + std::to_string(i), "G2", g_tilde_i);
  }

  element_t alpha;
  element_init_Zr(alpha, pairing_);
  element_random(alpha);
  master_key->InsertComponent("alpha", "ZR", alpha);

  element_pow_zn(g1, g, alpha);
  public_parameters->InsertComponent("g1", "G1", g1);

  element_t e_g1_g2;
  element_init_GT(e_g1_g2, pairing_);
  element_pairing(e_g1_g2, g1, g2);
  public_parameters->InsertComponent("e_g1_g2", "GT", e_g1_g2);

  auto *keys = new std::vector<Key *>(2);
  (*keys)[0] = master_key;
  (*keys)[1] = public_parameters;

  return keys;
}

Key *WildcardedSM9::KeyGen(Key *public_parameters, Key *master_key, const std::vector<std::string> &id_pattern) {
  assert(id_pattern.size() == id_pattern_size + 1); // id_pattern[0] is unused
  Key *private_key = new Key(Key::SECRET);
  private_key->SetIdPattern(id_pattern);

  element_t g, g1, g2, e_g1_g2;
  element_init_G1(g, pairing_);
  element_init_G1(g1, pairing_);
  element_init_G2(g2, pairing_);
  element_init_GT(e_g1_g2, pairing_);
  element_set(g, public_parameters->GetComponent("g", "G1"));
  element_set(g1, public_parameters->GetComponent("g1", "G1"));
  element_set(g2, public_parameters->GetComponent("g2", "G2"));
  element_set(e_g1_g2, public_parameters->GetComponent("e_g1_g2", "GT"));

  element_t alpha;
  element_init_Zr(alpha, pairing_);
  element_set(alpha, master_key->GetComponent("alpha", "ZR"));

  element_t r, t;
  element_init_Zr(r, pairing_);
  element_init_Zr(t, pairing_);
  element_random(r);
  element_random(t);

  //calculate K_1
  element_t K1;
  element_init_G2(K1, pairing_);

  //g_2^(\alpha / \alpha + p1)
  element_t g2_pow_alpha_div_alpha_p1, alpha_add_p1, alpha_div_alpha_p1, p1;
  element_init_Zr(p1, pairing_);

  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, id_pattern[1].c_str(), id_pattern[1].size());
  uint8_t output[BLAKE3_OUT_LEN];
  memset(output, 0, sizeof(output));
  blake3_hasher_finalize(&hasher, output, BLAKE3_OUT_LEN);
  element_from_hash(p1, output, BLAKE3_OUT_LEN);

  element_init_Zr(alpha_add_p1, pairing_);
  element_init_Zr(alpha_div_alpha_p1, pairing_);
  element_add(alpha_add_p1, alpha, p1);
  element_div(alpha_div_alpha_p1, alpha, alpha_add_p1);
  element_init_G2(g2_pow_alpha_div_alpha_p1, pairing_);
  element_pow_zn(g2_pow_alpha_div_alpha_p1, g2, alpha_div_alpha_p1);

  // (g1_hat * \prod g_hat_i^p_i)^r
  element_t prod_g_hat_i_p_i_r;
  element_init_G2(prod_g_hat_i_p_i_r, pairing_);
  element_set(prod_g_hat_i_p_i_r, public_parameters->GetComponent("g_hat_1"));

  element_t g_hat_i, g_hat_i_p_i;
  element_init_G2(g_hat_i, pairing_);
  element_init_G2(g_hat_i_p_i, pairing_);
  element_t p_i;
  element_init_Zr(p_i, pairing_);

  element_t R_i, T_i, O_i, g_hat_i_pi_r;
  element_init_G2(R_i, pairing_);
  element_init_G2(T_i, pairing_);
  element_init_G2(O_i, pairing_);
  element_init_G2(g_hat_i_pi_r, pairing_);

  for (int i = 1; i <= id_pattern_size; ++i) {

    element_set(g_hat_i, public_parameters->GetComponent("g_hat_" + std::to_string(i)));
    if (id_pattern[i] == "*") { // wildcard

      element_pow_zn(R_i, g_hat_i, r); // calculate R_i
      element_pow_zn(T_i, g_hat_i, t); // calculate T_i

      private_key->InsertComponent("R_" + std::to_string(i), "G2", R_i);
      private_key->InsertComponent("T_" + std::to_string(i), "G2", T_i);
    } else { // non-wildcard

      uint8_t p_hash[BLAKE3_OUT_LEN];
      blake3_hasher_update(&hasher, id_pattern[i].c_str(), id_pattern[i].size());
      memset(p_hash, 0, sizeof(p_hash));
      blake3_hasher_finalize(&hasher, p_hash, BLAKE3_OUT_LEN);
      element_from_hash(p_i, p_hash, BLAKE3_OUT_LEN);
      element_pow_zn(g_hat_i_p_i, g_hat_i, p_i);

      element_mul(prod_g_hat_i_p_i_r, prod_g_hat_i_p_i_r, g_hat_i_p_i);

      // calculate O_i
      element_pow_zn(g_hat_i_pi_r, g_hat_i_p_i, r);
      element_pow_zn(T_i, g_hat_i, t);
      element_div(O_i, T_i, g_hat_i_pi_r);
      private_key->InsertComponent("O_" + std::to_string(i), "G2", O_i);
    }
  }

  element_pow_zn(prod_g_hat_i_p_i_r, prod_g_hat_i_p_i_r, r);
  element_mul(K1, g2_pow_alpha_div_alpha_p1, prod_g_hat_i_p_i_r);
  private_key->InsertComponent("K1", "G2", K1);

  // calculate K2
  element_t K2;
  element_init_G1(K2, pairing_);
  element_t r_alpha_p1;
  element_init_Zr(r_alpha_p1, pairing_);
  element_mul(r_alpha_p1, r, alpha_add_p1);
  element_pow_zn(K2, g, r_alpha_p1);
  private_key->InsertComponent("K2", "G1", K2);

  // calculate K3
  element_t K3;
  element_init_G1(K3, pairing_);
  element_t t_alpha_p1;
  element_init_Zr(t_alpha_p1, pairing_);
  element_mul(t_alpha_p1, t, alpha_add_p1);
  element_pow_zn(K3, g, t_alpha_p1);
  private_key->InsertComponent("K3", "G1", K3);

  private_key->PrintKeyLength();

  return private_key;
}

Ciphertext *WildcardedSM9::Encrypt(element_s *m, const std::vector<std::string> &id_pattern, Key *public_parameters) {
  auto *ciphertext = new Ciphertext(id_pattern);
  element_t g, g1, g2, e_g1_g2;
  element_init_G1(g, pairing_);
  element_init_G1(g1, pairing_);
  element_init_G2(g2, pairing_);
  element_init_GT(e_g1_g2, pairing_);
  element_set(g, public_parameters->GetComponent("g", "G1"));
  element_set(g1, public_parameters->GetComponent("g1", "G1"));
  element_set(g2, public_parameters->GetComponent("g2", "G2"));
  element_set(e_g1_g2, public_parameters->GetComponent("e_g1_g2", "GT"));

  element_t s;
  element_init_Zr(s, pairing_);
  element_random(s);

  element_t p1_prime, p1_prime_s, g_p1_prime_s, g1_s;
  element_init_Zr(p1_prime, pairing_);
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, id_pattern[1].c_str(), id_pattern[1].size());
  uint8_t output[BLAKE3_OUT_LEN];
  memset(output, 0, sizeof(output));
  blake3_hasher_finalize(&hasher, output, BLAKE3_OUT_LEN);
  element_from_hash(p1_prime, output, BLAKE3_OUT_LEN);
  element_init_Zr(p1_prime_s, pairing_);
  element_mul(p1_prime_s, p1_prime, s);
  element_init_G1(g1_s, pairing_);
  element_pow_zn(g1_s, g1, s);
  element_init_G1(g_p1_prime_s, pairing_);
  element_pow_zn(g_p1_prime_s, g, p1_prime_s);
  element_t C1;
  element_init_G1(C1, pairing_);
  element_mul(C1, g1_s, g_p1_prime_s);

  element_t C2, C3;
  element_init_G2(C2, pairing_);
  element_set(C2, public_parameters->GetComponent("g_hat_1"));
  element_init_G2(C3, pairing_);
  element_set1(C3);

  element_t p_i_prime;
  element_t g_hat_i;
  element_t g_hat_i_p_i_prime;
  element_init_Zr(p_i_prime, pairing_);
  element_init_G2(g_hat_i, pairing_);
  element_init_G2(g_hat_i_p_i_prime, pairing_);

  //FIXME: bug
  for (int i = 1; i <= id_pattern_size; ++i) {
    element_set(g_hat_i, public_parameters->GetComponent("g_hat_" + std::to_string(i)));
    if (id_pattern[i] == "*") { // wildcard
      element_mul(C3, C3, g_hat_i);
    } else { // non-wildcard
      uint8_t p_hash[BLAKE3_OUT_LEN];
      blake3_hasher_update(&hasher, id_pattern[i].c_str(), id_pattern[i].size());
      memset(p_hash, 0, sizeof(p_hash));
      blake3_hasher_finalize(&hasher, p_hash, BLAKE3_OUT_LEN);
      element_from_hash(p_i_prime, p_hash, BLAKE3_OUT_LEN);
      element_pow_zn(g_hat_i_p_i_prime, g_hat_i, p_i_prime);
      element_mul(C2, C2, g_hat_i_p_i_prime);
    }
  }

  element_pow_zn(C2, C2, s);
  element_pow_zn(C3, C3, s);
  element_t C4;
  element_init_GT(C4, pairing_);
  element_pow_zn(C4, e_g1_g2, s);

  auto encap_key = KDF(C1, C2, C3, C4, id_pattern);

//  printf("EncapKey in Encryption: ");
//  for (int i = 0; i < BLAKE3_OUT_LEN; ++i) {
//    printf("%02x", *(encap_key + i));
//  }
//  printf("\n");
  ciphertext->SetEncapKey(encap_key, BLAKE3_OUT_LEN);
  ciphertext->SetEncapKeyLength(BLAKE3_OUT_LEN);

  ciphertext->InsertComponent("C1", "G1", C1);
  ciphertext->InsertComponent("C2", "G2", C2);
  ciphertext->InsertComponent("C3", "G2", C3);

  ciphertext->PrintCiphertextLength();

  return ciphertext;
}

element_s *WildcardedSM9::Decrypt(Ciphertext *ciphertext, Key *secret_key) {
  element_t K1, K2, K3;
  element_t C1, C2, C3;
  element_init_G2(K1, pairing_);
  element_init_G1(K2, pairing_);
  element_init_G1(K3, pairing_);
  element_set(K1, secret_key->GetComponent("K1", "G2"));
  element_set(K2, secret_key->GetComponent("K2", "G1"));
  element_set(K3, secret_key->GetComponent("K3", "G1"));
  element_init_G1(C1, pairing_);
  element_set(C1, ciphertext->GetComponent("C1", "G1"));
  element_init_G2(C2, pairing_);
  element_set(C2, ciphertext->GetComponent("C2", "G2"));
  element_init_G2(C3, pairing_);
  element_set(C3, ciphertext->GetComponent("C3", "G2"));

  auto P = secret_key->GetIdPattern();
  auto P_prime = ciphertext->GetIdPattern();

  element_t K1_prime;
  element_init_G2(K1_prime, pairing_);
  element_set(K1_prime, K1);

  blake3_hasher hasher;
  blake3_hasher_init(&hasher);

  element_t R_i, R_i_P_i_prime, T_i, O_i, p_i_prime;
  element_init_G2(R_i, pairing_);
  element_init_G2(T_i, pairing_);
  element_init_G2(O_i, pairing_);
  element_init_G2(R_i_P_i_prime, pairing_);
  element_init_Zr(p_i_prime, pairing_);
  uint8_t output[BLAKE3_OUT_LEN];

  for (int i = 1; i <= id_pattern_size; ++i) {
    if (P_prime[i] != "*" && P[i] == "*") { //R_i
      printf("[Decrypt] WBar(P') ^ W(P): %d\n", i);
      blake3_hasher_update(&hasher, P_prime[i].c_str(), P_prime[i].size());
      memset(output, 0, sizeof(output));
      blake3_hasher_finalize(&hasher, output, BLAKE3_OUT_LEN);
      element_from_hash(p_i_prime, output, BLAKE3_OUT_LEN);
      element_set(R_i, secret_key->GetComponent("R_" + std::to_string(i), "G2"));
      element_pow_zn(R_i_P_i_prime, R_i, p_i_prime);
      element_mul(K1_prime, K1_prime, R_i_P_i_prime);
    } else if (P_prime[i] == "*" && P[i] == "*") { //T_i
      element_mul(K1_prime, K1_prime, secret_key->GetComponent("T_" + std::to_string(i), "G2"));
    } else if (P_prime[i] == "*" && P[i] != "*") { //O_i
      element_mul(K1_prime, K1_prime, secret_key->GetComponent("O_" + std::to_string(i), "G2"));
    }
  }

  element_t B, e_K1_prime_C1, e_K2_C2, e_K3_C3;

  element_init_GT(B, pairing_);
  element_init_GT(e_K1_prime_C1, pairing_);
  element_init_GT(e_K2_C2, pairing_);
  element_init_GT(e_K3_C3, pairing_);
  element_pairing(e_K1_prime_C1, C1, K1_prime);
  element_pairing(e_K2_C2, K2, C2);
  element_pairing(e_K3_C3, K3, C3);
  element_div(B, e_K1_prime_C1, e_K2_C2);
  element_div(B, B, e_K3_C3);

  auto encap_key = KDF(C1, C2, C3, B, P_prime);
//  printf("EncapKey in Decryption: ");
//  for (int i = 0; i < BLAKE3_OUT_LEN; ++i) {
//    printf("%02x", *(encap_key + i));
//  }
//  printf("\n");

  return nullptr;
}

unsigned char *WildcardedSM9::KDF(element_s *C1, element_s *C2, element_s *C3, element_s *C4,
                                  const std::vector<std::string> &id_pattern) {
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  char hash_byte[4096];
  memset(hash_byte, 0, sizeof(hash_byte));
  unsigned char tmp_byte[512];
  memset(tmp_byte, 0, sizeof(tmp_byte));
  int c1_len = element_to_bytes(tmp_byte, C1);
  strncat(hash_byte, reinterpret_cast<const char *>(tmp_byte), c1_len);
  memset(tmp_byte, 0, sizeof(tmp_byte));
  int c2_len = element_to_bytes(tmp_byte, C2);
  strncat(hash_byte, reinterpret_cast<const char *>(tmp_byte), c2_len);
  memset(tmp_byte, 0, sizeof(tmp_byte));
  int c3_len = element_to_bytes(tmp_byte, C3);
  strncat(hash_byte, reinterpret_cast<const char *>(tmp_byte), c3_len);
  memset(tmp_byte, 0, sizeof(tmp_byte));
  int c4_len = element_to_bytes(tmp_byte, C4);
  strncat(hash_byte, reinterpret_cast<const char *>(tmp_byte), c4_len);

  uint8_t id_hash[BLAKE3_OUT_LEN];
  memset(id_hash, 0, sizeof(id_hash));
  char id_bytes[4096];
  memset(id_bytes, 0, sizeof(id_bytes));
  size_t id_len_total = 0;
  for (int i = 1; i <= id_pattern_size; ++i) {
    strncat(id_bytes, id_pattern[i].c_str(), id_pattern[i].length());
    id_len_total += id_pattern[i].length();
  }

  blake3_hasher_update(&hasher, id_bytes, id_len_total);
  blake3_hasher_finalize(&hasher, id_hash, BLAKE3_OUT_LEN);

  strncat(hash_byte, reinterpret_cast<const char *>(id_hash), BLAKE3_OUT_LEN);

  auto *output = new unsigned char[BLAKE3_OUT_LEN];
  memset(output, 0, BLAKE3_OUT_LEN * sizeof(unsigned char));
  blake3_hasher_update(&hasher, hash_byte, c1_len + c2_len + c3_len + c4_len + BLAKE3_OUT_LEN);
  blake3_hasher_finalize(&hasher, output, BLAKE3_OUT_LEN);

  return output;
}
