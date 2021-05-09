/* Copyright (C) 2019 Neo Huang - All Rights Reserved */

#include "flashroute/targets.h"

#include <fstream>
#include <memory>
#include <unordered_set>
#include <vector>

#include "absl/strings/numbers.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "flashroute/blacklist.h"
#include "flashroute/dcb_manager.h"
#include "flashroute/utils.h"
#include "glog/logging.h"
#include <boost/format.hpp>

namespace flashroute {

Targets::Targets(const uint8_t defaultSplitTtl, const uint32_t seed,
                 Blacklist* blacklist, BogonFilter* bogerFilter)
    : blacklist_(blacklist),
      bogerFilter_(bogerFilter),
      defaultSplitTtl_(defaultSplitTtl),
      seed_(seed) {}

DcbManager* Targets::loadTargetsFromFile(
    absl::string_view filePath, const uint8_t granularity,
    const bool LookupByPrefixSupport) const {
  DcbManager* dcbManager =
      new DcbManager(1000, granularity, seed_, LookupByPrefixSupport);
  if (filePath.empty()) {
    VLOG(2) << "Targets disabled.";
    return dcbManager;
  }

  VLOG(2) << "Load targets from file: " << filePath;
  auto filePathStr = std::string(filePath);
  std::ifstream in(filePathStr);
  int64_t count = 0;
  std::unordered_set<uint32_t> addressBlocks;
  for (std::string line; std::getline(in, line);) {
    if (!line.empty()) {
      auto result = parseIpFromStringToIpAddress(line);
      if (result == NULL) continue;
      auto ip = std::unique_ptr<IpAddress>(result);
      // Set ip address
      if ((blacklist_ == nullptr || !blacklist_->contains(*ip)) &&
          (bogerFilter_ == nullptr || !bogerFilter_->isBogonAddress(*ip))) {
        dcbManager->addDcb(*ip, defaultSplitTtl_);
      }
      count++;
    }
  }
  in.close();
  VLOG(2) << "Load " << count << " addresses from file.";

  return dcbManager;
}

DcbManager* Targets::generateTargetsFromNetwork(
    absl::string_view targetNetwork, const uint8_t granularity,
    const bool LookupByPrefixSupport) const {
  DcbManager* dcbManager =
      new DcbManager(1000, granularity, seed_, LookupByPrefixSupport);

  std::vector<absl::string_view> parts = absl::StrSplit(targetNetwork, "/");
  if (parts.size() != 2) {
    LOG(FATAL) << "Target network format is incorrect!!! " << targetNetwork;
  }

  uint32_t subnetPrefixLength = 0;

  if (!absl::SimpleAtoi(parts[1], &subnetPrefixLength)) {
    LOG(FATAL) << "Failed to parse the target network.";
  }

  IpAddress* targetBaseAddress =
      parseIpFromStringToIpAddress(std::string(parts[0]));

  IpAddress* targetNetworkFirstAddress_ =
      getFirstAddressOfBlock(*targetBaseAddress, subnetPrefixLength);
  IpAddress* targetNetworkLastAddress_ =
      getLastAddressOfBlock(*targetBaseAddress, subnetPrefixLength);

  if (*targetNetworkFirstAddress_ >= *targetNetworkLastAddress_) {
    LOG(FATAL) << "Ip address range is incorrect.";
  }

  LOG(INFO) << boost::format("The target network is from %1% to %2%.") %
                   parseIpFromIpAddressToString(*targetNetworkFirstAddress_) %
                   parseIpFromIpAddressToString(*targetNetworkLastAddress_);

  if (targetBaseAddress->isIpv4()) {
    uint64_t targetNetworkSize =
        static_cast<int64_t>(targetNetworkLastAddress_->getIpv4Address()) -
        static_cast<int64_t>(targetNetworkFirstAddress_->getIpv4Address()) + 1;

    uint64_t blockFactor_ =
        static_cast<uint64_t>(std::pow(2, 32 - granularity));
    uint64_t dcbCount = static_cast<uint64_t>(targetNetworkSize / blockFactor_);

    // set random seed.
    std::srand(seed_);
    uint32_t actualCount = 0;
    uint32_t bogonCount = 0;
    for (uint64_t i = 0; i < dcbCount; i++) {
      // randomly generate IP addresse avoid the first and last ip address
      // in the block.
      Ipv4Address tmp(targetNetworkFirstAddress_->getIpv4Address() +
                      ((i) << (32 - granularity)) +
                      (rand() % (blockFactor_ - 3)) + 2);

      if ((blacklist_ == nullptr || !blacklist_->contains(tmp)) &&
          (bogerFilter_ == nullptr || !bogerFilter_->isBogonAddress(tmp))) {
        dcbManager->addDcb(tmp, defaultSplitTtl_);
        actualCount++;
      } else if (bogerFilter_ != nullptr && bogerFilter_->isBogonAddress(tmp)) {
        bogonCount ++;
      }
    }
    VLOG(2) << boost::format("Created %1% entries (1 reserved dcb).") %
                   actualCount;
    LOG(INFO) << "BOGON COUNT " << bogonCount;
  } else {
    absl::uint128 targetNetworkSize =
        ntohll(targetNetworkLastAddress_->getIpv6Address()) -
        ntohll(targetNetworkFirstAddress_->getIpv6Address()) + 1;

    absl::uint128 blockFactor_ =
        static_cast<absl::uint128>(std::pow(2, 128 - granularity));
    absl::uint128 dcbCount =
        static_cast<absl::uint128>(targetNetworkSize / blockFactor_);

    // set random seed.
    absl::uint128 actualCount = 0;
    std::srand(seed_);
    for (absl::uint128 i = 0; i < dcbCount; i++) {
      // randomly generate IP addresse avoid the first and last ip address
      // in the block.
      Ipv6Address tmp(htonll(
          ntohll(targetNetworkFirstAddress_->getIpv6Address()) +
          ((i) << (128 - granularity)) + (rand() % (blockFactor_ - 3)) + 2));
      if (blacklist_ != nullptr && !blacklist_->contains(tmp)) {
        dcbManager->addDcb(tmp, defaultSplitTtl_);
        actualCount++;
      }
    }
    VLOG(2) << "Created " << actualCount << " entries (1 reserved dcb).";
  }

  return dcbManager;
}

}  // namespace flashroute
