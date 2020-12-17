/* Copyright (C) 2019 Neo Huang - All Rights Reserved */

#include "flashroute/targets.h"

#include <fstream>
#include <memory>
#include <unordered_set>
#include <vector>

#include "absl/strings/numbers.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include <boost/format.hpp>
#include "glog/logging.h"

#include "flashroute/blacklist.h"
#include "flashroute/dcb_manager.h"
#include "flashroute/utils.h"

namespace flashroute {

Targets::Targets(const uint8_t defaultSplitTtl, const uint32_t seed,
                 Blacklist* blacklist)
    : blacklist_(blacklist), defaultSplitTtl_(defaultSplitTtl), seed_(seed) {}

DcbManager* Targets::loadTargetsFromFile(absl::string_view filePath) const {
  DcbManager* dcbManager = new DcbManager(1000, 0, seed_);
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
      if (blacklist_ != nullptr && !blacklist_->contains(*ip)) {
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
    absl::string_view targetNetwork, const uint8_t granularity) const {
  DcbManager* dcbManager = new DcbManager(1000, 0, seed_);

  std::vector<absl::string_view> parts = absl::StrSplit(targetNetwork, "/");
  if (parts.size() != 2) {
    LOG(FATAL) << "Target network format is incorrect!!! " << targetNetwork;
  }

  uint32_t subnetPrefixLength = 0;

  if (!absl::SimpleAtoi(parts[1], &subnetPrefixLength)) {
    LOG(FATAL) << "Failed to parse the target network.";
  }

  uint32_t targetBaseAddress = parseIpFromStringToInt(std::string(parts[0]));

  Ipv4Address targetNetworkFirstAddress_ =
      getFirstAddressOfBlock(targetBaseAddress, subnetPrefixLength);
  Ipv4Address targetNetworkLastAddress_ =
      getLastAddressOfBlock(targetBaseAddress, subnetPrefixLength);

  if (targetNetworkFirstAddress_ >= targetNetworkLastAddress_) {
    LOG(FATAL) << boost::format("Ip address range is incorrect. [%1%, %2%]") %
                      targetNetworkFirstAddress_.getIpv4Address() %
                      targetNetworkLastAddress_.getIpv4Address();
  }

  LOG(INFO) << boost::format("The target network is from %1% to %2%.") %
                   parseIpFromIpAddressToString(targetNetworkFirstAddress_) %
                   parseIpFromIpAddressToString(targetNetworkLastAddress_);

  uint64_t targetNetworkSize =
      static_cast<int64_t>(targetNetworkLastAddress_.getIpv4Address()) -
      static_cast<int64_t>(targetNetworkFirstAddress_.getIpv4Address()) + 1;

  uint64_t blockFactor_ = static_cast<uint64_t>(std::pow(2, 32 - granularity));
  uint64_t dcbCount = static_cast<uint64_t>(targetNetworkSize / blockFactor_);

  // set random seed.
  std::srand(seed_);
  for (uint64_t i = 0; i < dcbCount; i++) {
    // randomly generate IP addresse avoid the first and last ip address
    // in the block.
    Ipv4Address tmp(targetNetworkFirstAddress_.getIpv4Address() +
                    ((i) << (32 - granularity)) +
                    (rand() % (blockFactor_ - 3)) + 2);
    if (blacklist_ != nullptr && !blacklist_->contains(tmp)) {
      dcbManager->addDcb(tmp, defaultSplitTtl_);
    }
  }
  VLOG(2) << boost::format("Created %1% entries (1 reserved dcb).") % dcbCount;

  return dcbManager;
}

}  // namespace flashroute
