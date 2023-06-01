//
// Created by fxy on 2023/3/16.
//

#ifndef WILDCARDED_SM9_INCLUDE_SCHEMES_WILDCARDED_SM9_H_
#define WILDCARDED_SM9_INCLUDE_SCHEMES_WILDCARDED_SM9_H_

#include "ibe/swibe.h"
#include <vector>

inline size_t id_pattern_size = 100;

class WildcardedSM9 : public SWIBE {
 public:
  WildcardedSM9();

  std::vector<Key *> *SetUp() override;

  Key *KeyGen(Key *public_parameters, Key *master_key, const std::vector<std::string> &id_pattern) override;

  Ciphertext *Encrypt(element_s *message, const std::vector<std::string> &id_pattern, Key *public_parameters) override;

  element_s *Decrypt(Ciphertext *ciphertext, Key *private_key) override;

  static unsigned char *KDF(element_s *C1,
                            element_s *C2,
                            element_s *C3,
                            element_s *C4,
                            const std::vector<std::string> &id_pattern);
};

#endif //WILDCARDED_SM9_INCLUDE_SCHEMES_WILDCARDED_SM9_H_
