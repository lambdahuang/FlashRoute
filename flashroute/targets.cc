/* Copyright (C) 2019 Neo Huang - All Rights Reserved */

#include "flashroute/targets.h"

#include <memory>
#include <fstream>
#include <unordered_set>

#include "flashroute/utils.h"
#include "flashroute/traceroute.h"

namespace flashroute {

void Targets::loadTargetsFromFile(const std::string& filePath,
                          Tracerouter* tracerouter) {
  if (filePath.empty()) {
    VLOG(2) << "Targets disabled.";
    return;
  }

  VLOG(2) << "Load targets from file: " << filePath;
  std::ifstream in(filePath);
  int64_t count = 0;
  std::unordered_set<uint32_t> addressBlocks;
  for (std::string line; getline(in, line);) {
    if (!line.empty()) {
      auto ip = std::unique_ptr<IpAddress>(parseIpFromStringToIpAddress(line));
      // Set ip address
      tracerouter->setDcbIpAddress(*ip);
      addressBlocks.insert((ip->getIpv4Address()>>8));
      count++;
    }
  }
  in.close();
  VLOG(2) << "Load " << count << " addresses from file.";

  uint32_t totalTargets = 1 << 24;
  count = 0;
  for (uint32_t i = 0; i < totalTargets; i ++) {
    if (addressBlocks.find(i) == addressBlocks.end()) {
      Ipv4Address pseudoIp((i << 8) + 5);
      int64_t blocklIndex = tracerouter->getDcbByIpAddress(pseudoIp, false);
      if (blocklIndex >= 0 && blocklIndex < tracerouter->getBlockCount()) {
        // Remove the destinations that are not in taget set.
        tracerouter->removeDcbElement(blocklIndex);
        count++;
      }
    }
  }
  VLOG(2) << "Remove " << count << " addresses.";
  return;
}

}  // namespace flashroute
