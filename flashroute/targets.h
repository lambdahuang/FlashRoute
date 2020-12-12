/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#pragma once

#include <string>

#include "flashroute/dcb_manager.h"
#include "absl/strings/string_view.h"

namespace flashroute {

class Targets {
 public:
  Targets(const uint8_t defaultSplitTtl, const uint32_t seed);

  // Load targets from file.
  DcbManager loadTargetsFromFile(absl::string_view filePath) const;

  // Generate targets from a range.
  DcbManager generateTargetsFromNetwork(absl::string_view targetNetwork,
                                        const uint8_t granularity) const;

 private:
  uint8_t defaultSplitTtl_;
  uint32_t seed_;

};

}  // namespace flashroute
