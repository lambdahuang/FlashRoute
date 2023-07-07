/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#pragma once

#include <chrono>
#include <functional>
#include <iostream>
#include <string>

#include <arpa/inet.h>
#include <netinet/ip.h>       // ip header
#include <netinet/ip_icmp.h>  // icmp header
#include <netinet/tcp.h>
#include <netinet/udp.h>  // udp header

#include "flashroute/address.h"

namespace flashroute {

enum class SocketType { UDP, ICMP, TCP };

const uint32_t kPacketMessageDefaultPayloadSize = 1500;

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

using PacketReceiverCallback =
    std::function<void(const IpAddress& destination, const IpAddress& responder,
                       uint16_t sourcePort, uint16_t destinationPort,
                       uint8_t distance, uint32_t rtt, bool fromDestination,
                       bool ipv4, void* packetHeader, size_t headerLen)>;

class Prober {
 public:
  virtual size_t packProbe(const IpAddress& destinationIp,
                           const IpAddress& sourceIp, uint16_t sourcePort,
                           uint16_t destPort, const uint8_t ttl,
                           uint8_t* packetBuffer) = 0;

  virtual void parseResponse(uint8_t* buffer, size_t size,
                             SocketType socketType) = 0;

  virtual void setChecksumOffset(int32_t checksumOffset) = 0;

  virtual uint64_t getChecksumMismatches() = 0;
  virtual uint64_t getDistanceAbnormalities() = 0;
  virtual uint64_t getOtherMismatches() = 0;
};

}  // namespace flashroute
