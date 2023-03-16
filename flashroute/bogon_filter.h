/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#pragma once

#include <unordered_set>
#include <vector>

#include "flashroute/address.h"
#include "flashroute/trie.h"

namespace flashroute {

class BogonFilter {
 public:
  explicit BogonFilter(const std::string& filePath);

  bool isBogonAddress(const IpAddress& ip);

 private:
  std::unique_ptr<TrieManager> trie_;
  bool initialized_;
};

}  // namespace flashroute
