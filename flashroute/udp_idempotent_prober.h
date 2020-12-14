/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#pragma once

#include <iostream>
#include <string>

#include "flashroute/prober.h"

namespace flashroute {

/**
 * UDP Prober handles packet construction and response parsing.
 *
 * Example:
 *
 * PacketReceiverCallback callback =
 *    [](const IpAddress& destination, const IpAddress& responder,
 *                    uint8_t distance, bool fromDestination) {
 *      // The tracerouting logic on response.
 *    };
 *
 * UdpProber prober(
 *    callback,   // Callback function to handle responses.
 *    0,          // Checksum offset to support discovery-optimized mode.
 *    1,          // 0 stands for preprobing, 1 stands for main probing.
 *    53,         // Destination port number.
 *    "message payload",  //payload message.
 *    false        // Not encode timestamp into probe so scan is idempotent.
 * );
 *
 * // Pass prober instance to network manager, so users can call
 * schedualProbeRemoteHost to issue probe or process responses in callback func.
 * NetworkManager networkManager(
 *  &prober,  // The prober to process packets.
 *  "eth0",   // The interface to send the probe.
 *  100000    // The packet sending rate.
 * );
 *
 */

class UdpIdempotentProber : public virtual Prober {
 public:
  UdpIdempotentProber(PacketReceiverCallback* callback,
                      const int32_t checksumOffset,
                      const uint8_t probePhaseCode,
                      const uint16_t destinationPort,
                      const std::string& payloadMessage,
                      const bool encodeTimestamp);

  // Construct probe.
  size_t packProbe(const IpAddress& destinationIp, const IpAddress& sourceIp,
                   const uint8_t ttl, uint8_t* packetBuffer) override;

  // Parse responses.
  void parseResponse(uint8_t* buffer, size_t size,
                     SocketType socketType) override;

  // Change checksum offset (support discovery-optimized mode.)
  void setChecksumOffset(int32_t checksumOffset);

  // Put here for testing purpose.
  uint16_t getDestAddrChecksum(const uint16_t* ipaddress,
                               const uint16_t offset) const;

  // Put here for testing purpose.
  uint16_t getChecksum(const uint8_t protocolValue, size_t packetLength,
                       const uint16_t* src_addr, const uint16_t* dest_addr,
                       uint16_t* buff) const;

  uint16_t getChecksum(uint16_t* buff, uint16_t offset) const;

  // Get metrics information
  uint64_t getChecksumMismatches() override;
  uint64_t getDistanceAbnormalities() override;
  uint64_t getOtherMismatches() override;

 private:
  PacketReceiverCallback* callback_;
  int32_t checksumOffset_;
  uint8_t probePhaseCode_;
  uint16_t destinationPort_;
  std::string payloadMessage_;
  bool encodeTimestamp_;

  // Metrics
  uint64_t checksumMismatches_;
  uint64_t distanceAbnormalities_;
  uint64_t otherMismatches_;
};

}  // namespace flashroute
