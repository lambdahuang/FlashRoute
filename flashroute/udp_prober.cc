/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#include "flashroute/udp_prober.h"

#include <netinet/ip.h>       // ip header
#include <netinet/ip_icmp.h>  // icmp header
#include <netinet/tcp.h>
#include <netinet/udp.h>  // udp header

#include <memory>
#include <cstring>

#include "glog/logging.h"
#include "flashroute/address.h"

namespace flashroute {

const uint8_t kUdpProtocol = 17;  // Default UDP protocol id.

// The maximum ttl we will explore.
const uint8_t kMaxTtl = 32;

UdpProber::UdpProber(PacketReceiverCallback* callback,
                     const int32_t checksumOffset, const uint8_t probePhaseCode,
                     const uint16_t destinationPort,
                     const std::string& payloadMessage,
                     const bool encodeTimestamp, const uint8_t ttlOffset) {
  probePhaseCode_ = probePhaseCode;
  callback_ = callback;
  checksumOffset_ = checksumOffset;
  payloadMessage_ = payloadMessage;
  destinationPort_ = htons(destinationPort);
  encodeTimestamp_ = encodeTimestamp;
  ttlOffset_ = ttlOffset;
  checksumMismatches_ = 0;
  distanceAbnormalities_ = 0;
  otherMismatches_ = 0;
  VLOG(2) << "UdpProber is initialized";
}

size_t UdpProber::packProbe(const IpAddress& destinationIp,
                            const IpAddress& sourceIp, const uint8_t ttl,
                            uint8_t* packetBuffer) {
  uint32_t destinationIpDecimal =
      htonl((dynamic_cast<const Ipv4Address&>(destinationIp)).getIpv4Address());
  uint32_t sourceIpDecimal =
      htonl((dynamic_cast<const Ipv4Address&>(sourceIp)).getIpv4Address());

  struct PacketUdp* packet =
      reinterpret_cast<struct PacketUdp*>(packetBuffer);

  uint16_t timestamp = getTimestamp();
  // Fabricate the IP header or we can use the
  // standard header structures but assign our own values.
  memset(&packet->ip, 0, sizeof(packet->ip));
  packet->ip.ip_v = 4;
  packet->ip.ip_hl = sizeof(packet->ip) >> 2;
  packet->ip.ip_dst =
      *(reinterpret_cast<struct in_addr*>(&destinationIpDecimal));
  packet->ip.ip_src = *(reinterpret_cast<struct in_addr*>(&sourceIpDecimal));
  packet->ip.ip_p = kUdpProtocol;  // UDP protocol
  packet->ip.ip_ttl = ttl;
  // ipid: 5-bit for encoding intiial TTL, 1 bit for encoding probeType, 10-bit
  // for encoding timestamp.
  // 0x3FF = 2^10 to extract first 10-bit of timestamp
  uint16_t ipid = ((ttl - ttlOffset_) & 0x1F) | ((probePhaseCode_ & 0x1) << 5);
  int32_t packetExpectedSize = 128;

  if (encodeTimestamp_) {
    ipid = ipid | ((timestamp & 0x3FF) << 6);
    // packet-size encode 6-bit timestamp
    // (((timestamp >> 10) & 0x3F) << 6): the rest 6-bit of timestamp
    packetExpectedSize = packetExpectedSize | (((timestamp >> 10) & 0x3F) << 1);
  }
  // In OSX, please use: packet->ip.ip_len = packetExpectedSize;
  // Otherwise, you will have an Errno-22.
#if defined(__APPLE__) || defined(__MACH__)
  packet->ip.ip_len = packetExpectedSize;
  packet->ip.ip_id = ipid;
#else
  packet->ip.ip_len = htons(packetExpectedSize);
  packet->ip.ip_id = htons(ipid);
#endif


  memset(&packet->udp, '\0', sizeof(packet->udp));
  memcpy(packet->payload, payloadMessage_.c_str(), payloadMessage_.size());

#ifdef __FAVOR_BSD
  packet->udp.uh_dport = destinationPort_;
  packet->udp.uh_sport = getChecksum(
      reinterpret_cast<uint16_t*>(&destinationIpDecimal), checksumOffset_);
  packet->udp.uh_ulen = htons(packetExpectedSize - sizeof(packet->ip));

  // if you set a checksum to zero, your kernel's IP stack should fill in
  // the correct checksum during transmission
  // packet->udp.uh_sum = 0;
  packet->udp.uh_sum = getChecksum(
      kUdpProtocol, packetExpectedSize - sizeof(packet->ip),
      reinterpret_cast<uint16_t*>(&sourceIpDecimal),
      reinterpret_cast<uint16_t*>(&destinationIpDecimal),
      reinterpret_cast<uint16_t*>(packetBuffer + sizeof(struct ip)));
#else
  packet->udp.dest = destinationPort_;
  packet->udp.source = getChecksum(
      reinterpret_cast<uint16_t*>(&destinationIpDecimal), checksumOffset_);
  packet->udp.len = htons(packetExpectedSize - sizeof(packet->ip));

  // if you set a checksum to zero, your kernel's IP stack should fill in
  // the correct checksum during transmission
  // packet->udp.uh_sum = 0;
  packet->udp.check = getChecksum(
      kUdpProtocol, packetExpectedSize - sizeof(packet->ip),
      reinterpret_cast<uint16_t*>(&sourceIpDecimal),
      reinterpret_cast<uint16_t*>(&destinationIpDecimal),
      reinterpret_cast<uint16_t*>(packetBuffer + sizeof(struct ip)));
#endif

  return packetExpectedSize;
}

void UdpProber::setChecksumOffset(int32_t checksumOffset) {
  checksumOffset_ = checksumOffset;
}

void UdpProber::parseResponse(uint8_t* buffer, size_t size,
                              SocketType socketType) {
  if (socketType != SocketType::ICMP || size < 56) return;
  struct PacketIcmp* parsedPacket =
      reinterpret_cast<struct PacketIcmp*>(buffer);
  struct PacketUdp* residualUdpPacket =
      reinterpret_cast<struct PacketUdp*>(buffer + 28);

  uint32_t destination = 0;
  uint32_t responder = 0;
  int16_t distance = 0;
  bool fromDestination = false;

#ifdef __FAVOR_BSD
  if (getChecksum(
          reinterpret_cast<uint16_t*>(&residualUdpPacket->ip.ip_dst.s_addr),
          checksumOffset_) != residualUdpPacket->udp.uh_sport) {
    // Checksum unmatched.
    checksumMismatches += 1;
    return;
  }
#else
  if (getChecksum(
          reinterpret_cast<uint16_t*>(&residualUdpPacket->ip.ip_dst.s_addr),
          checksumOffset_) != residualUdpPacket->udp.source) {
    // Checksum unmatched.
    checksumMismatches_ += 1;
    return;
  }
#endif
  destination = ntohl(residualUdpPacket->ip.ip_dst.s_addr);
  responder = ntohl(parsedPacket->ip.ip_src.s_addr);

#if defined(__APPLE__) || defined(__MACH__)
  uint16_t replyIpId = parsedPacket->ip.ip_id;
  uint16_t replyIpLen = parsedPacket->ip.ip_len;
  uint16_t probeIpLen = residualUdpPacket->ip.ip_len;
  uint16_t probeIpId = residualUdpPacket->ip.ip_id;
#else
  uint16_t replyIpId = ntohs(parsedPacket->ip.ip_id);
  uint16_t replyIpLen = ntohs(parsedPacket->ip.ip_len);
  uint16_t probeIpLen = ntohs(residualUdpPacket->ip.ip_len);
  uint16_t probeIpId = ntohs(residualUdpPacket->ip.ip_id);
#endif

  uint32_t sentTimestamp = ((probeIpId >> 6) & 0x3FF) |
                           (((probeIpLen >> 1) & 0x3F) << 10);
  uint8_t probePhase = (probeIpId >> 5) & 0x1;

  int64_t receivedTimestamp = getTimestamp();
  uint32_t rtt = static_cast<uint32_t>(receivedTimestamp - sentTimestamp +
                                       kTimestampSlot) %
                 kTimestampSlot;

  int16_t initialTTL = static_cast<int16_t>(probeIpId & 0x1F);
  if (initialTTL == 0) initialTTL = 32;
  initialTTL += ttlOffset_;

  if (parsedPacket->icmp.icmp_type == 3 &&
      (parsedPacket->icmp.icmp_code == 3 || parsedPacket->icmp.icmp_code == 2 ||
       parsedPacket->icmp.icmp_code == 1)) {
    // Unreachable from Destination
    fromDestination = true;
    // Distance = initial distance - remaining distance + 1
    distance = initialTTL - residualUdpPacket->ip.ip_ttl + 1;
  }  else if (parsedPacket->icmp.icmp_type == 3) {
    // Other Unreachable
    fromDestination = false;
    distance = initialTTL - residualUdpPacket->ip.ip_ttl + 1;
    return;
  } else if (parsedPacket->icmp.icmp_type == 11 &&
             parsedPacket->icmp.icmp_code == 0) {
    // Time Exceeded
    fromDestination = false;
    distance = initialTTL;
  } else {
    // Other packets.
    otherMismatches_++;
    return;
  }

  if (distance <= ttlOffset_ || distance > (kMaxTtl + ttlOffset_)) {
    distanceAbnormalities_ += 1;
    return;
  }

  Ipv4Address ipv4Destination(destination);
  Ipv4Address ipv4Responder(responder);

  (*callback_)(ipv4Destination, ipv4Responder, static_cast<uint8_t>(distance),
               rtt, fromDestination, true, buffer, size);
}

uint16_t UdpProber::getTimestamp() const {
  int64_t millisecond = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now().time_since_epoch())
                            .count();
  millisecond = millisecond % kTimestampSlot;
  return static_cast<uint16_t>(millisecond);
}

uint16_t UdpProber::getChecksum(const uint16_t* ipAddress,
                                     uint16_t offset) const {
  uint32_t sum = 0;
  sum += ntohs(ipAddress[0]);
  sum += ntohs(ipAddress[1]);

  // keep only the last 16 bits of the 32 bit calculated sum and add the
  // carries
  sum = (sum & 0xFFFF) + (sum >> 16);

  // Take the bitwise complement of sum
  sum = ~sum;
  return htons(((uint16_t)sum + offset));
}

uint16_t UdpProber::getChecksum(const uint8_t protocolValue,
                                     size_t packetLength,
                                     const uint16_t* sourceIpAddress,
                                     const uint16_t* destinationIpAddress,
                                     uint16_t* buff) const {
  /* Check if the tcp length is even or odd.  Add padding if odd. */
  if ((packetLength % 2) == 1) {
    // Empty space in the ip buffer should be 0 anyway.
    buff[packetLength] = 0;
    packetLength += 1;  // incrase length to make even.
  }

  uint32_t sum = 0;
  /* add the pseudo header */
  sum += ntohs(sourceIpAddress[0]);
  sum += ntohs(sourceIpAddress[1]);
  sum += ntohs(destinationIpAddress[0]);
  sum += ntohs(destinationIpAddress[1]);
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

uint64_t UdpProber::getChecksumMismatches() {
  return checksumMismatches_;
}

uint64_t UdpProber::getDistanceAbnormalities() {
  return distanceAbnormalities_;
}

uint64_t UdpProber::getOtherMismatches() {
  return otherMismatches_;
}

}  // namespace flashroute
