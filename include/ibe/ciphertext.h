//
// Created by alan on 19-4-26.
//

#ifndef ABELIB_CIPHERTEXT_H
#define ABELIB_CIPHERTEXT_H

#include <string>
#include <vector>
#include <pbc/pbc.h>
#include <unordered_map>
#include "utils/blake3.h"

class Ciphertext
{
public:
  Ciphertext();

  explicit Ciphertext(std::vector<std::string> id_pattern);

  element_s *GetComponent(const std::string &s, const std::string &group);

  void InsertComponent(const std::string &s, const std::string &group, element_s *component);

  std::unordered_map<std::string, element_s *> *GetComponents(const std::string &group);

  element_s *GetComponent(const std::string &s);

  void SetEncapKey(unsigned char *key, int length);

  unsigned char *GetEncapKey();

  void SetEncapKeyLength(size_t length);

  [[nodiscard]] size_t GetEncapKeyLength() const;

  void SetIdPattern(std::vector<std::string> id_pattern);

  std::vector<std::string> GetIdPattern();

  void PrintCiphertext();

  size_t PrintCiphertextLength();

private:
  std::vector<std::string> id_pattern_;
  unsigned char *encap_key_;
  size_t encap_key_len_ = BLAKE3_OUT_LEN;
  std::unordered_map<std::string, element_s *> *g1_components;
  std::unordered_map<std::string, element_s *> *g2_components;
  std::unordered_map<std::string, element_s *> *gt_components;
  std::unordered_map<std::string, element_s *> *zr_components;
};

#endif //ABELIB_CIPHERTEXT_H
