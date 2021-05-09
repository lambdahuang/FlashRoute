/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#pragma once

#include <unordered_set>
#include <string>
#include <memory>

#include "flashroute/address.h"

namespace flashroute {

struct TrieNode {
  explicit TrieNode(bool isEnd) : end(isEnd) {}
  // The current bit
  bool bit;
  // Whether this is an end node.
  bool end;

  // Two branches.
  std::unique_ptr<TrieNode> zero;
  std::unique_ptr<TrieNode> one;
};

class TrieManager {
 public:
  TrieManager(bool ipv4);
  void insert(const IpAddress& dest, const uint32_t length);

  // Check whether the address is contained by a prefix in the tree.
  bool checkAddressContained(const IpAddress& dest);

 private:
  bool ipv4_;
  std::unique_ptr<TrieNode> root_;
  std::unique_ptr<
      std::unordered_set<IpNetwork*, IpNetworkHash, IpNetworkEquality>>
      coarseMap_;
};

}  // namespace flashroute
