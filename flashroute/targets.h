/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#pragma once

#include <string>

#include "flashroute/traceroute.h"

namespace flashroute {

class Targets {
 public:
    // Load targets from file.
  static void loadTargetsFromFile(const std::string& filePath,
                          Tracerouter* tracerouter);
};

}  // namespace flashroute
