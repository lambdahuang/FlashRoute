/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#include "flashroute/udp_idempotent_prober.h"

#include <netinet/ip.h>       // ip header
#include <netinet/ip_icmp.h>  // icmp header
#include <netinet/tcp.h>
#include <netinet/udp.h>  // udp header

#include <memory>
#include <cstring>

#include "glog/logging.h"

namespace flashroute {

const uint8_t kUdpProtocol = 17;  // Default UDP protocol id.

// The maximum ttl we will explore.
const uint8_t kMaxTtl = 32;
// The default IPID. Don't set to 0 cause it would compel OS to give it a random
// value.
const uint16_t kDefaultIPID = 1234;

UdpIdempotentProber::UdpIdempotentProber(PacketReceiverCallback* callback,
                                         const int32_t checksumOffset,
                                         const uint8_t probePhaseCode,
                                         const uint16_t destinationPort,
                                         const std::string& payloadMessage,
                                         const bool encodeTimestamp,
                                         const uint8_t ttlOffset) {
  probePhaseCode_ = probePhaseCode;
  callback_ = callback;
  checksumOffset_ = checksumOffset;
  ttlOffset_ = ttlOffset;
  payloadMessage_ = payloadMessage;
  destinationPort_ = htons(destinationPort);
  encodeTimestamp_ = encodeTimestamp;
  checksumMismatches_ = 0;
  distanceAbnormalities_ = 0;
  otherMismatches_ = 0;
  VLOG(2) << "UdpIdempotentProber is initialized";
}

size_t UdpIdempotentProber::packProbe(const IpAddress& destinationIp,
                                      const IpAddress& sourceIp,
                                      const uint8_t ttl,
                                      uint8_t* packetBuffer) {
  uint32_t destinationIpDecimal =
      htonl((dynamic_cast<const Ipv4Address&>(destinationIp)).getIpv4Address());
  uint32_t sourceIpDecimal =
      htonl((dynamic_cast<const Ipv4Address&>(sourceIp)).getIpv4Address());

  struct PacketUdp* packet =
      reinterpret_cast<struct PacketUdp*>(packetBuffer);

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

  int32_t packetExpectedSize = 0;
  uint8_t groupOfDestination =
      static_cast<uint8_t>((destinationIpDecimal % 7) + 1);

  // packet-size encodes 3-bit destination group.
  packetExpectedSize = (groupOfDestination & 0x7) << 6;
  // packet-size encodes 6-bit: 5-bit TTL and 1 bit for encoding protoType.
  packetExpectedSize = packetExpectedSize | ((ttl - ttlOffset_) & 0x1F) |
                       ((probePhaseCode_ & 0x1) << 5);

  // In OSX, please use: packet->ip.ip_len = packetExpectedSize;
  // Otherwise, you will have an Errno-22.
#if defined(__APPLE__) || defined(__MACH__)
  packet->ip.ip_len = packetExpectedSize;
  packet->ip.ip_id = getDestAddrChecksum(
      reinterpret_cast<uint16_t*>(&destinationIpDecimal), checksumOffset_);
#else
  packet->ip.ip_len = htons(packetExpectedSize);
  packet->ip.ip_id = htons(getDestAddrChecksum(
      reinterpret_cast<uint16_t*>(&destinationIpDecimal), checksumOffset_));
#endif

  memset(&packet->udp, '\0', sizeof(packet->udp));
  memcpy(packet->payload, payloadMessage_.c_str(), payloadMessage_.size());

#ifdef __FAVOR_BSD
  packet->udp.uh_dport = destinationPort_;
  packet->udp.uh_sport =
      getChecksum(reinterpret_cast<uint16_t*>(packetBuffer), checksumOffset_);
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
  packet->udp.source =
      getChecksum(reinterpret_cast<uint16_t*>(packetBuffer), checksumOffset_);
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

void UdpIdempotentProber::setChecksumOffset(int32_t checksumOffset) {
  checksumOffset_ = checksumOffset;
}

void UdpIdempotentProber::parseResponse(uint8_t* buffer, size_t size,
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

// Verify ipid(checksum of destination) with destination in quotation.
#if defined(__APPLE__) || defined(__MACH__)
  if (getDestAddrChecksum(
          reinterpret_cast<uint16_t*>(&residualUdpPacket->ip.ip_dst.s_addr),
          checksumOffset_) != residualUdpPacket->ip.ip_id) {
    // Checksum unmatched.
    checksumMismatches_ += 1;
    return;
  }
#else
  if (getDestAddrChecksum(
          reinterpret_cast<uint16_t*>(&residualUdpPacket->ip.ip_dst.s_addr),
          checksumOffset_) != ntohs(residualUdpPacket->ip.ip_id)) {
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

  uint8_t probePhase = (probeIpLen >> 5) & 0x1;
  uint32_t rtt = 0;
  int16_t initialTTL = static_cast<int16_t>(probeIpLen & 0x1F);
  if (initialTTL == 0) initialTTL = 32;
  initialTTL+=ttlOffset_;

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

uint16_t UdpIdempotentProber::getDestAddrChecksum(const uint16_t* ipAddress,
                                                  const uint16_t offset) const {
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

uint16_t UdpIdempotentProber::getChecksum(const uint8_t protocolValue,
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

uint16_t UdpIdempotentProber::getChecksum(uint16_t* buff,
                                          uint16_t offset) const {
  uint32_t sum = 0;

  /*
   * calculate the checksum for the tcp header and payload
   * len_tcp represents number of 8-bit bytes,
   * we are working with 16-bit words so divide len_tcp by 2.
   */
  for (uint32_t i = 0; i < 10; i++) {
    if (i == 4) {
      sum += buff[i] & 0xFF00;
    } else if (i == 5 || i == 1) {
      // do nothing
    } else {
      sum += buff[i];
    }
  }

  // keep only the last 16 bits of the 32 bit calculated sum and add the
  // carries
  sum = (sum & 0xFFFF) + (sum >> 16);
  // sum += (sum >> 16);

  // Take the bitwise complement of sum
  sum = ~sum;
  return htons(((uint16_t)sum + offset));
}

// Get metrics information

uint64_t UdpIdempotentProber::getChecksumMismatches() {
  return checksumMismatches_;
}

uint64_t UdpIdempotentProber::getDistanceAbnormalities() {
  return distanceAbnormalities_;
}

uint64_t UdpIdempotentProber::getOtherMismatches() {
  return otherMismatches_;
}

}  // namespace flashroute
