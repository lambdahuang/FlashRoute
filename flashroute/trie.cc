#include "trie.h"

#include "glog/logging.h"

namespace flashroute {

bool getSignificantBitFromIpv4AddressByIndex(const IpAddress& addr, int position) {
  auto decimalAddr = addr.getIpv4Address();
  return (decimalAddr >> (32 - position)) & 1;
}

TrieManager::TrieManager(bool ipv4)
    : ipv4_(ipv4), root_(std::make_unique<TrieNode>(false)) {}

bool TrieManager::checkAddressContained(const IpAddress& dest) {
  TrieNode* tmp = root_.get();
  if (ipv4_) {
    for (int i = 1; i <= 32; i++) {
      if (tmp->end == true) return true;
      bool result = getSignificantBitFromIpv4AddressByIndex(dest, i);
      if (result) {
        if (tmp->one.get() == nullptr) {
          return tmp->end;
        }
        tmp = tmp->one.get();
      } else {
        if (tmp->zero.get() == nullptr) {
          return tmp->end;
        }
        tmp = tmp->zero.get();
      }
    }
  }
  return false;
}

void TrieManager::insert(const IpAddress& dest, const uint32_t length) {
  if (dest.isIpv4() != ipv4_) {
    // LOG(FATAL) << "Address type mismatch.";
    return;
  }
  TrieNode* tmp = root_.get();
  if (ipv4_) {
    if (length > 32)
      LOG(FATAL) << "Prefix length is greater than the max length of address.";
    for (uint32_t i = 1; i <= length; i++) {
      bool result = getSignificantBitFromIpv4AddressByIndex(dest, i);
      if (result) {
        if (tmp->one.get() == nullptr) {
          tmp->one = std::make_unique<TrieNode>(false);
        }
        tmp = tmp->one.get();
      } else {
        if (tmp->zero.get() == nullptr) {
          tmp->zero = std::make_unique<TrieNode>(false);
        }
        tmp = tmp->zero.get();
      }
    }
    tmp->end = true;
  }
}

}  // namespace flashroute