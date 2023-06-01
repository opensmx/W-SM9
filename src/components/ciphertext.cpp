//
// Created by alan on 19-4-26.
//

#include "ibe/ciphertext.h"

#include <iostream>
#include <utility>
#include <cstring>

Ciphertext::Ciphertext() {
  encap_key_ = nullptr;
  g1_components = new std::unordered_map<std::string, element_s *>();
  g2_components = new std::unordered_map<std::string, element_s *>();
  gt_components = new std::unordered_map<std::string, element_s *>();
  zr_components = new std::unordered_map<std::string, element_s *>();
}

Ciphertext::Ciphertext(std::vector<std::string> id_pattern) {
  id_pattern_ = std::move(id_pattern);
  encap_key_ = nullptr;
  g1_components = new std::unordered_map<std::string, element_s *>();
  g2_components = new std::unordered_map<std::string, element_s *>();
  gt_components = new std::unordered_map<std::string, element_s *>();
  zr_components = new std::unordered_map<std::string, element_s *>();
}

element_s *Ciphertext::GetComponent(const std::string &s, const std::string &group) {
  std::unordered_map<std::string, element_s *>::iterator it;
  if (group == "G1") {
    it = g1_components->find(s);
    if (it == g1_components->end()) {
      return nullptr;
    } else {
      return (*it).second;
    }
  } else if (group == "G2") {
    it = g2_components->find(s);
    if (it == g2_components->end()) {
      return nullptr;
    } else {
      return (*it).second;
    }
  } else if (group == "GT") {
    it = gt_components->find(s);
    if (it == gt_components->end()) {
      return nullptr;
    } else {
      return (*it).second;
    }
  } else if (group == "ZR") {
    it = zr_components->find(s);
    if (it == zr_components->end()) {
      return nullptr;
    } else {
      return (*it).second;
    }
  }
  return nullptr;
}

void Ciphertext::InsertComponent(const std::string &s, const std::string &group, element_s *component) {
  auto *insert_component = new element_t[1];
  element_init_same_as(*insert_component, component);
  element_set(*insert_component, component);
  if (group == "G1") {
    g1_components->insert(std::pair<std::string, element_s *>(s, *insert_component));
  } else if (group == "G2") {
    g2_components->insert(std::pair<std::string, element_s *>(s, *insert_component));
  } else if (group == "GT") {
    gt_components->insert(std::pair<std::string, element_s *>(s, *insert_component));
  } else if (group == "ZR") {
    zr_components->insert(std::pair<std::string, element_s *>(s, *insert_component));
  }
}

std::unordered_map<std::string, element_s *> *Ciphertext::GetComponents(const std::string &group) {
  if (group == "G1") {
    return g1_components;
  } else if (group == "G2") {
    return g2_components;
  } else if (group == "GT") {
    return gt_components;
  } else if (group == "ZR") {
    return zr_components;
  }
  return nullptr;
}

element_s *Ciphertext::GetComponent(const std::string &s) {
  element_s *res;

  res = GetComponent(s, "G1");
  if (res != nullptr) {
    return res;
  }
  res = GetComponent(s, "G2");
  if (res != nullptr) {
    return res;
  }
  res = GetComponent(s, "GT");
  if (res != nullptr) {
    return res;
  }
  res = GetComponent(s, "ZR");
  if (res != nullptr) {
    return res;
  }

  return nullptr;
}

unsigned char *Ciphertext::GetEncapKey() {
  return encap_key_;
}
void Ciphertext::SetEncapKey(unsigned char *key, int len) {
  encap_key_ = new unsigned char[len];
  memcpy(encap_key_, key, len);
}
void Ciphertext::SetEncapKeyLength(size_t length) {
  encap_key_len_ = length;
}
size_t Ciphertext::GetEncapKeyLength() const {
  return encap_key_len_;
}

void Ciphertext::PrintCiphertext() {
  std::cout << std::endl;
  std::cout << "id: " << std::endl;
  std::cout << "[";
  for (int i = 0; i < id_pattern_.size(); ++i) {
    if (i) { std::cout << ", "; }
    std::cout << id_pattern_[i];
  }
  std::cout << "]\n";

//  std::cout << id << std::endl;
  std::cout << std::endl;
  std::unordered_map<std::string, element_s *>::iterator it;
  std::cout << "G1: " << std::endl;
  for (it = g1_components->begin(); it != g1_components->end(); ++it) {
    std::cout << it->first << ": " << std::endl;
    element_printf("%B\n", it->second);
  }
  std::cout << std::endl;
  std::cout << "G2: " << std::endl;
  for (it = g2_components->begin(); it != g2_components->end(); ++it) {
    std::cout << it->first << ": " << std::endl;
    element_printf("%B\n", it->second);
  }
  std::cout << std::endl;
  std::cout << "GT: " << std::endl;
  for (it = gt_components->begin(); it != gt_components->end(); ++it) {
    std::cout << it->first << ": " << std::endl;
    element_printf("%B\n", it->second);
  }
  std::cout << std::endl;
  std::cout << "ZR: " << std::endl;
  for (it = zr_components->begin(); it != zr_components->end(); ++it) {
    std::cout << it->first << ": " << std::endl;
    element_printf("%B\n", it->second);
  }
  std::cout << std::endl;

  if (encap_key_ != nullptr) {
    printf("EncapKey: ");
    for (int i = 0; i < encap_key_len_; ++i) {
      printf("%02x", *(encap_key_ + i));
    }
    printf("\n");
  }
}

size_t Ciphertext::PrintCiphertextLength() {
  size_t res = 0;
  std::unordered_map<std::string, element_s *>::iterator it;
  for (it = g1_components->begin(); it != g1_components->end(); ++it) {
    res += element_length_in_bytes(it->second);
  }

  for (it = g2_components->begin(); it != g2_components->end(); ++it) {
    res += element_length_in_bytes(it->second);
  }

  for (it = gt_components->begin(); it != gt_components->end(); ++it) {
    res += element_length_in_bytes(it->second);
  }

  for (it = zr_components->begin(); it != zr_components->end(); ++it) {
    res += element_length_in_bytes(it->second);
  }
  std::cout << "ct_length: " << res << " (bytes)\n";
  return res;
}

void Ciphertext::SetIdPattern(std::vector<std::string> id_pattern) {
  id_pattern_ = std::move(id_pattern);
}
std::vector<std::string> Ciphertext::GetIdPattern() {
  return id_pattern_;
}
