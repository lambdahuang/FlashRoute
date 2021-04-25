/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#include "flashroute/output_parser.h"

#include <unordered_map>

namespace flashroute {

uint32_t kDataElementLength = 39;

void updateDcbsBasedOnHistory(const std::string& filepath,
                              DcbManager* dcbManager) {
  OutputParser outputParser{filepath};

  std::unordered_map<IpAddress*, uint8_t, IpAddressHash, IpAddressEquality>
      maxObservedRouteLength;
  // Loads the outputs and update the analysis program.
  while (outputParser.hasNext()) {
    ParsedElement& element = outputParser.next();
    auto result =  maxObservedRouteLength.find(element.destination);
    if (result == maxObservedRouteLength.end()) {
      maxObservedRouteLength.insert(
          {element.destination->clone(), element.distance});
    } else {
      // Update the max distance for each destiantion.
      maxObservedRouteLength[element.destination] = std::max(
          maxObservedRouteLength[element.destination], element.distance);
    }
  }

  for (auto element : maxObservedRouteLength) {
    // Searchs the dcbs based on prefix and update.
    auto* result = dcbManager->getDcbsByAddress(*element.first);
    if (result == nullptr) continue;
    for (auto* dcb : *result) {
      dcb->updateSplitTtl(element.second, true);
    }
  }

  // Clean up
  while (maxObservedRouteLength.size() > 0) {
    auto element = maxObservedRouteLength.begin();
    auto keyAddress = element->first;
    maxObservedRouteLength.erase(keyAddress);
    delete keyAddress;
  }
}

OutputParser::OutputParser(const std::string& output) {
  inFile_.open(output, std::ios::in | std::ios::binary);
}

OutputParser::~OutputParser() {
  if (inFile_.is_open()) {
    inFile_.close();
  }
}

bool OutputParser::hasNext() {
  return (inFile_.is_open() && inFile_.peek() != EOF);
}

ParsedElement& OutputParser::next() {
  if (hasNext()) {
    inFile_.read(reinterpret_cast<char*>(&rawNext_), kDataElementLength);
    if (inFile_.gcount() != kDataElementLength) {
      // Underflow
    } else {
      if (rawNext_.ipv4) {
        next_.destination = &next_.destinationV4;
        next_.responder = &next_.responderV4;
        next_.destinationV4 = Ipv4Address(rawNext_.destination[0]);
        next_.responderV4 = Ipv4Address(rawNext_.responder[0]);
      } else {
        next_.destination = &next_.destinationV6;
        next_.responder = &next_.responderV6;
        next_.destinationV6 = Ipv6Address(
            *reinterpret_cast<absl::uint128*>(rawNext_.destination));
        next_.responderV6 =
            Ipv6Address(*reinterpret_cast<absl::uint128*>(rawNext_.responder));
      }
      next_.distance = rawNext_.distance;
      next_.fromDestination = rawNext_.fromDestination;
      next_.rtt = rawNext_.rtt;
    }
  }
  return next_;
}

}  // namespace flashroute
