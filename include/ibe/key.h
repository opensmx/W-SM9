//
// Created by alan on 19-4-26.
//

#ifndef ABELIB_KEY_H
#define ABELIB_KEY_H

#include <pbc/pbc.h>
#include <string>
#include <vector>
#include <unordered_map>

class Key {
 public:
  enum KeyType {
    PUBLIC, MASTER, SECRET
  };
 protected:
  KeyType type_;
  std::vector<std::string> id_pattern_;
  std::unordered_map<std::string, element_s *> *g1_components_;
  std::unordered_map<std::string, element_s *> *g2_components_;
  std::unordered_map<std::string, element_s *> *gt_components_;
  std::unordered_map<std::string, element_s *> *zr_components_;

 public:
  explicit Key(Key::KeyType type);

  Key::KeyType GetType();

  void SetType(Key::KeyType type);

  void SetIdPattern(std::vector<std::string> id_pattern);

  std::vector<std::string> GetIdPattern();

  element_s *GetComponent(const std::string &s, const std::string &group);

  void InsertComponent(const std::string &s, const std::string &group, element_s *component);

  std::unordered_map<std::string, element_s *> *GetComponents(const std::string &group);

  element_s *GetComponent(const std::string &s);

  void PrintKey();

  size_t PrintKeyLength();
};

#endif //ABELIB_KEY_H
