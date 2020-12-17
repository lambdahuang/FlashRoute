/* Copyright (C) 2019 Neo Huang - All Rights Reserved */


#include <netinet/ip6.h>      // struct ip6_hdr
#include <netinet/icmp6.h>  // icmp header
#include <netinet/tcp.h>
#include <netinet/udp.h>  // udp header

#include <memory>
#include <cstring>

#include "glog/logging.h"
#include "flashroute/address.h"
#include "flashroute/udp_prober_v6.h"
#include "flashroute/utils.h"

namespace flashroute {

#define IP6_HDRLEN 40  // IPv6 header length
#define ICMP_HDRLEN 8  // ICMP header length
#define FLASHROUTE_HDRLEN 8  // FlashRoute header minimum length

const uint8_t kUdpProtocol = IPPROTO_UDP;  // Default UDP protocol id.

// The maximum ttl we will explore.
const uint8_t kMaxTtl = 32;

// 2^16 wrap-around interval for timestamp of UDP probe.
const uint32_t kTimestampSlot = 0xFFFFFFFF;

UdpProberIpv6::UdpProberIpv6(PacketReceiverCallback* callback,
                             const int32_t checksumOffset,
                             const uint8_t probePhaseCode,
                             const uint16_t destinationPort,
                             const std::string& payloadMessage) {
  probePhaseCode_ = probePhaseCode;
  callback_ = callback;
  checksumOffset_ = checksumOffset;
  payloadMessage_ = payloadMessage;
  destinationPort_ = htons(destinationPort);
  checksumMismatches_ = 0;
  distanceAbnormalities_ = 0;
  otherMismatches_ = 0;
  VLOG(2) << "UdpProber is initialized";
}

size_t UdpProberIpv6::packProbe(const IpAddress& destinationIp,
                            const IpAddress& sourceIp, const uint8_t ttl,
                            uint8_t* packetBuffer) {
  absl::uint128 destinationIpDecimal =
      (dynamic_cast<const Ipv6Address&>(destinationIp)).getIpv6Address();
  absl::uint128 sourceIpDecimal =
      (dynamic_cast<const Ipv6Address&>(sourceIp)).getIpv6Address();

  struct PacketUdpIpv6* packet =
      reinterpret_cast<struct PacketUdpIpv6*>(packetBuffer);

  uint16_t timestamp = getTimestamp();

  uint32_t packetExpectedSize =
      IP6_HDRLEN + ICMP_HDRLEN + FLASHROUTE_HDRLEN + payloadMessage_.size();

  // Copy data right next to the flashroute header.
  memcpy(packet->payload + FLASHROUTE_HDRLEN, payloadMessage_.c_str(),
         payloadMessage_.size());

  packet->flashrouteHeader.initialTtl = ttl;
  packet->flashrouteHeader.timestamp = timestamp;
  packet->flashrouteHeader.probeStatus = probePhaseCode_;

  memset(&packet->udp, 0, sizeof(packet->udp));
  memset(&packet->ip, 0, sizeof(packet->ip));

  // Fabricate the IP header or we can use the
  // standard header structures but assign our own values.
  // 4 bits version is set to 6
  // 8 bits is set to 0 (No Specific traffic)
  uint32_t flowLabel = 0;  // flow label 20 bits;
  packet->ip.ip6_ctlun.ip6_un1.ip6_un1_flow =
      htonl((6 << 28) | (0 << 20) | flowLabel);
  packet->ip.ip6_ctlun.ip6_un1.ip6_un1_nxt = kUdpProtocol;
  packet->ip.ip6_ctlun.ip6_un1.ip6_un1_hlim = ttl;

  memcpy(&(packet->ip.ip6_dst), &destinationIpDecimal, sizeof(absl::uint128));
  memcpy(&(packet->ip.ip6_src), &sourceIpDecimal, sizeof(absl::uint128));

  // In OSX, please use: packet->ip.ip_len = packetExpectedSize;
  // Otherwise, you will have an Errno-22.
  // TODO(neohuang) set the correct payload length
#if defined(__APPLE__) || defined(__MACH__)
  packet->ip.ip6_ctlun.ip6_un1.ip6_un1_plen = packetExpectedSize;
#else
  packet->ip.ip6_ctlun.ip6_un1.ip6_un1_plen =
      htons(packetExpectedSize - IP6_HDRLEN);
#endif

#ifdef __FAVOR_BSD
  packet->udp.uh_dport = destinationPort_;
  packet->udp.uh_sport = getChecksum(
      reinterpret_cast<uint16_t*>(&destinationIpDecimal), checksumOffset_);
  packet->udp.uh_ulen = htons(packetExpectedSize - IP6_HDRLEN);

  // if you set a checksum to zero, your kernel's IP stack should fill in
  // the correct checksum during transmission
  // packet->udp.uh_sum = 0;
  packet->udp.uh_sum = getChecksum(
      kUdpProtocol, packetExpectedSize - sizeof(packet->ip),
      reinterpret_cast<uint16_t*>(&sourceIpDecimal),
      reinterpret_cast<uint16_t*>(&destinationIpDecimal),
      reinterpret_cast<uint16_t*>(packetBuffer + sizeof(struct ip6_hdr)));

#else
  packet->udp.dest = destinationPort_;
  packet->udp.source = getChecksum(
      reinterpret_cast<uint16_t*>(&destinationIpDecimal), checksumOffset_);
  packet->udp.len = htons(packetExpectedSize - IP6_HDRLEN);

  // if you set a checksum to zero, your kernel's IP stack should fill in
  // the correct checksum during transmission
  // packet->udp.check= 0;
  packet->udp.check = getChecksum(
      kUdpProtocol, packetExpectedSize - sizeof(packet->ip),
      reinterpret_cast<uint16_t*>(&sourceIpDecimal),
      reinterpret_cast<uint16_t*>(&destinationIpDecimal),
      reinterpret_cast<uint16_t*>(packetBuffer + sizeof(struct ip6_hdr)));
#endif

  return packetExpectedSize;
}

void UdpProberIpv6::setChecksumOffset(int32_t checksumOffset) {
  checksumOffset_ = checksumOffset;
}

void UdpProberIpv6::parseResponse(uint8_t* buffer, size_t size,
                              SocketType socketType) {
  if (socketType != SocketType::ICMP || size < 96) return;
  struct PacketIcmpIpv6* parsedPacket =
      reinterpret_cast<struct PacketIcmpIpv6*>(buffer);
  struct PacketUdpIpv6* residualUdpPacket =
      reinterpret_cast<struct PacketUdpIpv6*>(buffer + 48);
  if (parsedPacket->ip.ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_ICMPV6) return;

  absl::uint128 destination = 0;
  absl::uint128 responder = 0;
  int16_t distance = 0;
  bool fromDestination = false;


#ifdef __FAVOR_BSD
  if (getChecksum(
          reinterpret_cast<uint16_t*>(&residualUdpPacket->ip.ip6_dst),
          checksumOffset_) != residualUdpPacket->udp.uh_sport) {
    // Checksum unmatched.
    checksumMismatches += 1;
    return;
  }
#else
  if (getChecksum(
          reinterpret_cast<uint16_t*>(&residualUdpPacket->ip.ip6_dst),
          checksumOffset_) != residualUdpPacket->udp.source) {
    // Checksum unmatched.
    checksumMismatches_ += 1;
    return;
  }
#endif

  memcpy(&destination, &residualUdpPacket->ip.ip6_dst, sizeof(absl::uint128));
  memcpy(&responder, &parsedPacket->ip.ip6_src, sizeof(absl::uint128));

  uint32_t sentTimestamp = residualUdpPacket->flashrouteHeader.timestamp;
  uint8_t probePhase = residualUdpPacket->flashrouteHeader.probeStatus;
  int16_t initialTTL =
      static_cast<int16_t>(residualUdpPacket->flashrouteHeader.initialTtl);

  int64_t receivedTimestamp = getTimestamp();
  uint32_t rtt = static_cast<uint32_t>(receivedTimestamp - sentTimestamp +
                                       kTimestampSlot) %
                 kTimestampSlot;
  if (probePhase != probePhaseCode_) return;

  if (residualUdpPacket->udp.source !=
      getChecksum(reinterpret_cast<uint16_t*>(&destination), checksumOffset_))
    return;

  if (initialTTL == 0) initialTTL = 32;

  if (parsedPacket->icmp.icmp6_type == 1 &&
      (parsedPacket->icmp.icmp6_code == 4 ||
       parsedPacket->icmp.icmp6_code == 3)) {
    // Unreachable from Destination
    fromDestination = true;
    // Distance = initial distance - remaining distance + 1
    distance =
        initialTTL - residualUdpPacket->ip.ip6_ctlun.ip6_un1.ip6_un1_hlim + 1;
  }  else if (parsedPacket->icmp.icmp6_type == 1) {
    // Other Unreachable
    fromDestination = false;
    distance =
        initialTTL - residualUdpPacket->ip.ip6_ctlun.ip6_un1.ip6_un1_hlim + 1;
    return;
  } else if (parsedPacket->icmp.icmp6_type == 3 &&
             parsedPacket->icmp.icmp6_code == 0) {
    // Time Exceeded
    fromDestination = false;
    distance = initialTTL;
  } else {
    // Other packets.
    otherMismatches_++;
    return;
  }

  if (distance <= 0 || distance > kMaxTtl) {
    distanceAbnormalities_ += 1;
    return;
  }

  Ipv6Address ipv4Destination(destination);
  Ipv6Address ipv4Responder(responder);

  (*callback_)(ipv4Destination, ipv4Responder, static_cast<uint8_t>(distance),
               rtt, fromDestination, false, buffer, size);
}

uint16_t UdpProberIpv6::getTimestamp() const {
  int64_t millisecond = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now().time_since_epoch())
                            .count();
  millisecond = millisecond % kTimestampSlot;
  return static_cast<uint16_t>(millisecond);
}

uint16_t UdpProberIpv6::getChecksum(const uint16_t* ipAddress,
                                             uint16_t offset) const {
  uint32_t sum = 0;
  for (int i = 0; i < 8; i ++) {
    sum += ntohs(ipAddress[i]);
  }

  // keep only the last 16 bits of the 32 bit calculated sum and add the
  // carries
  sum = (sum & 0xFFFF) + (sum >> 16);

  // Take the bitwise complement of sum
  sum = ~sum;
  return htons(((uint16_t)sum + offset));
}

uint16_t UdpProberIpv6::getChecksum(const uint8_t protocolValue,
                                     size_t packetLength,
                                     const uint16_t* sourceIpAddress,
                                     const uint16_t* destinationIpAddress,
                                     uint16_t* buff) const {
  /* Check if the content length is even or odd.  Add padding if odd. */
  if ((packetLength % 2) == 1) {
    // Empty space in the ip buffer should be 0 anyway.
    buff[packetLength] = 0;
    packetLength += 1;  // incrase length to make even.
  }

  uint32_t sum = 0;
  /* add the pseudo header */
  for (int i = 0; i < 8; i ++) {
    sum += ntohs(sourceIpAddress[i]);
    sum += ntohs(destinationIpAddress[i]);
  }
  sum += packetLength;   // already in host format.
  sum += protocolValue;  // already in host format.

  /*
   * calculate the checksum for the tcp header and payload
   * len_tcp represents number of 8-bit bytes,
   * we are working with 16-bit words so divide len_tcp by 2.
   */
  for (uint32_t i = 0; i < (packetLength / 2); i++) {
    sum += ntohs(buff[i]);
  }

  // keep only the last 16 bits of the 32 bit calculated sum and add the
  // carries
  sum = (sum & 0xFFFF) + (sum >> 16);
  // sum += (sum >> 16);

  // Take the bitwise complement of sum
  sum = ~sum;
  return htons(((uint16_t)sum));
}

// Get metrics information

uint64_t UdpProberIpv6::getChecksumMismatches() {
  return checksumMismatches_;
}

uint64_t UdpProberIpv6::getDistanceAbnormalities() {
  return distanceAbnormalities_;
}

uint64_t UdpProberIpv6::getOtherMismatches() {
  return otherMismatches_;
}

}  // namespace flashroute
