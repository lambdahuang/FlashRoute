/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#pragma once

#include <cstdint>
#include <string>
#include <memory>
#include <fstream>

#include "flashroute/address.h"
#include "flashroute/dcb_manager.h"

namespace flashroute {

void updateDcbsBasedOnHistory(const std::string& filepath,
                              DcbManager* dcbManager);

// This is used to cast the response element stored in a binary file.
struct DataElementCast {
  uint32_t destination[4];
  uint32_t responder[4];
  uint32_t rtt;
  uint8_t distance;
  uint8_t fromDestination;
  uint8_t ipv4;
} __attribute__((packed));

struct ParsedElement {
  IpAddress* destination;
  IpAddress* responder;
  Ipv4Address destinationV4;
  Ipv4Address responderV4;
  Ipv6Address destinationV6;
  Ipv6Address responderV6;
  uint32_t rtt;
  uint8_t distance;
  bool fromDestination;
  bool ipv4;
};

// Update splitting point for each dcb based on the history probing results.
void updateDcbsBasedOnHistory(const std::string& filepath,
                              DcbManager* dcbManager);

class OutputParser {
 public:
  explicit OutputParser(const std::string& output);
  ~OutputParser();

  ParsedElement& next();

  bool hasNext();

 private:
  std::ifstream inFile_;
  ParsedElement next_;
  DataElementCast rawNext_;
  bool isEnd_;

  void readOneElement();
};

}  // namespace flashroute
