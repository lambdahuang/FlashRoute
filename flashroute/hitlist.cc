/* Copyright (C) 2019 Neo Huang - All Rights Reserved */

#include "flashroute/hitlist.h"

#include <memory>
#include <fstream>
#include <limits>
#include <string>
#include <vector>

#include "absl/strings/str_split.h"
#include "flashroute/traceroute.h"
#include "flashroute/utils.h"

namespace flashroute {

void Hitlist::loadHitlist(const std::string& filePath,
                          Tracerouter* tracerouter) {
  if (filePath.empty()) {
    LOG(INFO) << "Hitlist disabled.";
    return;
  }

  LOG(INFO) << "Load hitlist from file: " << filePath;
  std::ifstream in(filePath);
  int64_t count = 0;
  for (std::string line; getline(in, line);) {
    if (!line.empty()) {
      std::vector<std::string> subs =
          absl::StrSplit(line, "\t");
      // The minimum length of IP addresses is greater/equal than 7 (1.1.1.1)
      if (subs.size() != 3 || subs[subs.size() - 1].size() < 7) continue;
      int32_t confidence = std::stoi(subs[subs.size()-2]);
      auto ip = std::unique_ptr<IpAddress>(
          parseIpFromStringToIpAddress(subs[subs.size() - 1]));
      if (confidence > 0) {
        // tracerouter->setDcbIpAddress(*ip);
        count++;
      }
    }
  }
  in.close();
  LOG(INFO) << count << " load addresses from hitlist.";
}

}  // namespace flashroute
