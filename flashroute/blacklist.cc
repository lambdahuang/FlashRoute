/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#include "flashroute/blacklist.h"

#include "glog/logging.h"

#include <fstream>
#include <limits>
#include <string>
#include <vector>

#include <boost/format.hpp>
#include "absl/strings/numbers.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"

#include "flashroute/traceroute.h"
#include "flashroute/utils.h"

namespace flashroute {

void Blacklist::removeAddressFromFile(const std::string& filePath,
                                         Tracerouter* tracerouter) {
  if (filePath.empty()) {
    LOG(INFO) << "Blacklist disabled.";
    return;
  }
  LOG(INFO) << "Load blacklist from file: " << filePath;
  std::ifstream in(filePath);
  if (!in) {
    LOG(ERROR) << "Failed to load blacklist.";
  }
  int64_t count = 0;
  for (std::string line; getline(in, line);) {
    if (!line.empty()) {
      count += removeAddressBlock(tracerouter, line);
    }
  }
  in.close();
  LOG(INFO) << count << " blacklist addresses have been removed.";
}

void Blacklist::removeReservedAddress(Tracerouter* tracerouter) {
  std::vector<std::string> reservedAddresses = {
      "0.0.0.0/8",      "10.0.0.0/8",     "100.64.0.0/10", "127.0.0.0/8",
      "169.254.0.0/16", "172.16.0.0/12",  "192.0.0.0/24",  "192.0.2.0/24",
      "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
      "203.0.113.0/24", "224.0.0.0/4",    "240.0.0.0/4"};

  int64_t removedAddressCount = 0;
  for (const auto& reservedBlock : reservedAddresses) {
    removedAddressCount += removeAddressBlock(tracerouter, reservedBlock);
  }
  LOG(INFO) << removedAddressCount << " reserved addresses have been removed.";
}

int64_t Blacklist::removeAddressBlock(Tracerouter* tracerouter,
                                     const std::string& ipBlock) {
  std::vector<absl::string_view> parts = absl::StrSplit(ipBlock, "/");
  uint32_t prefixLength = 0;
  if (parts.size() == 1 || !absl::SimpleAtoi(parts[1], &prefixLength)) {
    prefixLength = 32;
  }

  uint32_t prefixAddress = parseIpFromStringToInt(std::string(parts[0]));

  Ipv4Address ipBlockStart =
      getFirstAddressOfBlock(prefixAddress, prefixLength);
  Ipv4Address ipBlockEnd = getLastAddressOfBlock(prefixAddress, prefixLength);

  // Convert the range of IP addresses to the corresponding range of block
  // ids.
  // int64_t dcbStartIndex = tracerouter->getDcbByIpAddress(ipBlockStart, false);
  // int64_t dcbEndIndex = tracerouter->getDcbByIpAddress(ipBlockEnd, false);

  int64_t removedElementCount = 0;
  // For /24 block probing, each block contains 2^8 = 256 ip
  // for (int64_t tmp = dcbStartIndex; tmp <= dcbEndIndex; tmp += 1) {
  //   if (tracerouter->removeDcbElement(tmp) > -2) {
  //     // Remove block successfully.
  //     removedElementCount++;
  //   }
  // }
  return removedElementCount;
}

}  // namespace flashroute
