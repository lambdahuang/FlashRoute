/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#pragma once

#include <string>

#include "flashroute/blacklist.h"
#include "flashroute/dcb_manager.h"
#include "absl/strings/string_view.h"

namespace flashroute {

class Targets {
 public:
  Targets(const uint8_t defaultSplitTtl, const uint32_t seed,
          Blacklist* blacklist);

  // Load targets from file.
  DcbManager* loadTargetsFromFile(absl::string_view filePath,
                                  const uint8_t granularity,
                                  const bool preprobingSupport) const;

  // Generate targets from a range.
  DcbManager* generateTargetsFromNetwork(absl::string_view targetNetwork,
                                         const uint8_t granularity,
                                         const bool preprobingSupport) const;

 private:
  Blacklist* blacklist_;
  uint8_t defaultSplitTtl_;
  uint32_t seed_;
  uint32_t granularity_;

};

}  // namespace flashroute
