//
// Created by fxy on 2023/3/16.
//

#ifndef WILDCARDED_SM9_SRC_IBE_IBE_H_
#define WILDCARDED_SM9_SRC_IBE_IBE_H_
#include <pbc/pbc.h>
#include <vector>
#include "key.h"
#include "ciphertext.h"

class SWIBE {
 protected:
  pairing_t pairing_{};
 public:
  pairing_t *GetPairing();

  virtual std::vector<Key *> *SetUp() = 0;

  virtual Key *KeyGen(Key *public_parameters, Key *master_key, const std::vector<std::string> &id_pattern) = 0;

  virtual Ciphertext *Encrypt(element_s *message,
                              const std::vector<std::string> &id_pattern,
                              Key *public_parameters) = 0;

  virtual element_s *Decrypt(Ciphertext *ciphertext, Key *private_key) = 0;
};

#endif //WILDCARDED_SM9_SRC_IBE_IBE_H_
