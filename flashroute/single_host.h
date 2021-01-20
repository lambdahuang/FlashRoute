/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#pragma once

#include <string>
#include <memory>
#include <unordered_map>
#include <tuple>

#include "flashroute/dcb_manager.h"
#include "flashroute/network.h"
#include "flashroute/address.h"

namespace flashroute {

class SingleHost {
 public:
  SingleHost(const uint16_t srcPort, const uint16_t dstPort,
             const uint8_t ttlOffset);

  ~SingleHost();

  void startScan(const std::string& target, const std::string& interface);

  bool parseIcmpProbing(const IpAddress& destination,
                        const IpAddress& responder, uint8_t distance,
                        uint32_t rtt, bool fromDestination, bool ipv4,
                        void* packetBuffer, uint32_t packetLen);

 private:
  uint16_t srcPort_;
  uint16_t dstPort_;
  uint8_t ttlOffset_;

  std::unordered_map<uint8_t, std::tuple<std::shared_ptr<IpAddress>, uint32_t>>*
      results_;
};

}  // namespace flashroute

