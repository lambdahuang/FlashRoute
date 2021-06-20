#include "bogon_filter.h"

#include <algorithm>
#include <fstream>

#include "absl/strings/numbers.h"
#include "absl/strings/str_split.h"
#include "flashroute/utils.h"
#include "glog/logging.h"

namespace flashroute {

const uint32_t kNormalizeBgpPrefix = 32;

BogonFilter::BogonFilter(const std::string& filePath) {
  initialized_ = false;
  trie_ = std::make_unique<TrieManager>(true);
  if (filePath.empty()) return;
  std::ifstream inFile(filePath, std::ios::in);

  std::string line;
  while (std::getline(inFile, line)) {
    if (line.at(0) == '>') {
      auto tmpLine = line.substr(1);

      std::vector<absl::string_view> elements = absl::StrSplit(tmpLine, " ");
      auto network = elements[0];
      std::vector<absl::string_view> parts = absl::StrSplit(network, "/");
      if (parts.size() != 2) {
        LOG(FATAL) << "Target network format is incorrect!!! " << elements[0];
      }

      uint32_t subnetPrefixLength = 0;
      if (!absl::SimpleAtoi(parts[1], &subnetPrefixLength)) {
        LOG(FATAL) << "Failed to parse the target network.";
      }

      std::unique_ptr<IpAddress> targetBaseAddress{
          parseIpFromStringToIpAddress(std::string(parts[0]))};

      subnetPrefixLength = std::min(kNormalizeBgpPrefix, subnetPrefixLength);
      trie_->insert(*targetBaseAddress, subnetPrefixLength);
    }
  }
  initialized_ = true;
}

bool BogonFilter::isBogonAddress(const IpAddress& ip) {
  if (initialized_) {
    return !trie_->checkAddressContained(ip);
  } else {
    return false;
  }
}


}  // namespace flashroute
