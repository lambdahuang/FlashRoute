/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#pragma once

#include <chrono>
#include <iostream>
#include <string>
#include <functional>

#include <arpa/inet.h>
#include <netinet/ip.h>       // ip header
#include <netinet/ip_icmp.h>  // icmp header
#include <netinet/tcp.h>
#include <netinet/udp.h>  // udp header

namespace flashroute {

enum class SocketType { UDP, ICMP, TCP };

const uint32_t kPacketMessageDefaultPayloadSize = 256;

struct PacketIcmp {
  struct ip ip;
  struct icmp icmp;
} __attribute__((packed));

struct PacketUdp {
  struct ip ip;
  struct udphdr udp;
  char payload[kPacketMessageDefaultPayloadSize];
} __attribute__((packed));

struct PacketTcp {
  struct ip ip;
  struct tcphdr tcp;
  char payload[kPacketMessageDefaultPayloadSize];
} __attribute__((packed));

using PacketReceiverCallback = std::function<void(
    uint32_t destination, uint32_t responder, uint8_t distance,
    bool fromDestination, uint32_t rtt, uint8_t probePhase, uint16_t replyIpid,
    uint8_t replyTtl, uint32_t replySize, uint32_t probeSize,
    uint16_t probeIpid, uint16_t probeSourcePort,
    uint16_t probeDestinationPort)>;

class Prober {
 public:
  // Metrics
  uint64_t checksumMismatches;
  uint64_t distanceAbnormalities;

  virtual size_t packProbe(const uint32_t destinationIp,
                           const uint32_t sourceIp, const uint8_t ttl,
                           uint8_t* packetBuffer) = 0;

  virtual void parseResponse(uint8_t* buffer, size_t size,
                             SocketType socketType) = 0;

  virtual void setChecksumOffset(int32_t checksumOffset) = 0;
};

}  // namespace flashroute
