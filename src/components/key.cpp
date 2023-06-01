//
// Created by alan on 19-4-26.
//

#include "ibe/key.h"
#include <iostream>

Key::Key(Key::KeyType type) {
  this->type_ = type;

  g1_components_ = new std::unordered_map<std::string, element_s *>();
  g2_components_ = new std::unordered_map<std::string, element_s *>();
  gt_components_ = new std::unordered_map<std::string, element_s *>();
  zr_components_ = new std::unordered_map<std::string, element_s *>();
}

Key::KeyType Key::GetType() {
  return type_;
}

void Key::SetType(Key::KeyType type) {
  this->type_ = type;
}

void Key::SetIdPattern(std::vector<std::string> id_pattern) {
  id_pattern_ = std::move(id_pattern);
}
std::vector<std::string> Key::GetIdPattern() {
  return id_pattern_;
}

element_s *Key::GetComponent(const std::string &s, const std::string &group) {
  std::unordered_map<std::string, element_s *>::iterator it;
  if (group == "G1") {
    it = g1_components_->find(s);
    if (it == g1_components_->end()) {
      return nullptr;
    } else {
      return (*it).second;
    }
  } else if (group == "G2") {
    it = g2_components_->find(s);
    if (it == g2_components_->end()) {
      return nullptr;
    } else {
      return (*it).second;
    }
  } else if (group == "GT") {
    it = gt_components_->find(s);
    if (it == gt_components_->end()) {
      return nullptr;
    } else {
      return (*it).second;
    }
  } else if (group == "ZR") {
    it = zr_components_->find(s);
    if (it == zr_components_->end()) {
      return nullptr;
    } else {
      return (*it).second;
    }
  }
  return nullptr;
}

void Key::InsertComponent(const std::string &s, const std::string &group, element_s *component) {
  auto *insert_component = new element_t[1];
  element_init_same_as(*insert_component, component);
  element_set(*insert_component, component);
  if (group == "G1") {
    g1_components_->insert(std::pair<std::string, element_s *>(s, *insert_component));
  } else if (group == "G2") {
    g2_components_->insert(std::pair<std::string, element_s *>(s, *insert_component));
  } else if (group == "GT") {
    gt_components_->insert(std::pair<std::string, element_s *>(s, *insert_component));
  } else if (group == "ZR") {
    zr_components_->insert(std::pair<std::string, element_s *>(s, *insert_component));
  }
}

std::unordered_map<std::string, element_s *> *Key::GetComponents(const std::string &group) {
  if (group == "G1") {
    return g1_components_;
  } else if (group == "G2") {
    return g2_components_;
  } else if (group == "GT") {
    return gt_components_;
  } else if (group == "ZR") {
    return zr_components_;
  }
  return nullptr;
}

element_s *Key::GetComponent(const std::string &s) {
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

void Key::PrintKey() {
  std::cout << std::endl;
  std::unordered_map<std::string, element_s *>::iterator it;
  std::cout << "G1: " << std::endl;
  for (it = g1_components_->begin(); it != g1_components_->end(); ++it) {
    std::cout << it->first << ": " << std::endl;
    element_printf("%B\n", it->second);
  }
  std::cout << std::endl;
  std::cout << "G2: " << std::endl;
  for (it = g2_components_->begin(); it != g2_components_->end(); ++it) {
    std::cout << it->first << ": " << std::endl;
    element_printf("%B\n", it->second);
  }
  std::cout << std::endl;
  std::cout << "GT: " << std::endl;
  for (it = gt_components_->begin(); it != gt_components_->end(); ++it) {
    std::cout << it->first << ": " << std::endl;
    element_printf("%B\n", it->second);
  }
  std::cout << std::endl;
  std::cout << "ZR: " << std::endl;
  for (it = zr_components_->begin(); it != zr_components_->end(); ++it) {
    std::cout << it->first << ": " << std::endl;
    element_printf("%B\n", it->second);
  }
  std::cout << std::endl;
}

size_t Key::PrintKeyLength() {
  size_t res = 0;
  std::unordered_map<std::string, element_s *>::iterator it;
  for (it = g1_components_->begin(); it != g1_components_->end(); ++it) {
    res += element_length_in_bytes(it->second);
  }

  for (it = g2_components_->begin(); it != g2_components_->end(); ++it) {
    res += element_length_in_bytes(it->second);
  }

  for (it = gt_components_->begin(); it != gt_components_->end(); ++it) {
    res += element_length_in_bytes(it->second);
  }

  for (it = zr_components_->begin(); it != zr_components_->end(); ++it) {
    res += element_length_in_bytes(it->second);
  }
  std::cout << "key_length: " << res << " (bytes)\n";
  return res;
}