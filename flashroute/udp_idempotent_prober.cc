/* Copyright (C) 2019 Neo Huang - All Rights Reserved */


#include <netinet/ip.h>       // ip header
#include <netinet/ip_icmp.h>  // icmp header
#include <netinet/tcp.h>
#include <netinet/udp.h>  // udp header

#include <memory>
#include <cstring>

#include "glog/logging.h"
#include "flashroute/udp_idempotent_prober.h"

namespace flashroute {

const uint8_t kUdpProtocol = 17;  // Default UDP protocol id.

// The maximum ttl we will explore.
const uint8_t kMaxTtl = 32;
// The default IPID.
const uint8_t kDefaultIPID = 0;

UdpIdempotentProber::UdpIdempotentProber(PacketReceiverCallback* callback,
                     const int32_t checksumOffset, const uint8_t probePhaseCode,
                     const uint16_t destinationPort,
                     const std::string& payloadMessage,
                     const bool encodeTimestamp) {
  probePhaseCode_ = probePhaseCode;
  callback_ = callback;
  checksumOffset_ = checksumOffset;
  payloadMessage_ = payloadMessage;
  destinationPort_ = htons(destinationPort);
  encodeTimestamp_ = encodeTimestamp;
  checksumMismatches_ = 0;
  distanceAbnormalities_ = 0;
}

size_t UdpIdempotentProber::packProbe(const uint32_t destinationIp,
                            const uint32_t sourceIp, const uint8_t ttl,
                            uint8_t* packetBuffer) {
  struct PacketUdp* packet =
      reinterpret_cast<struct PacketUdp*>(packetBuffer);

  // Fabricate the IP header or we can use the
  // standard header structures but assign our own values.
  memset(&packet->ip, 0, sizeof(packet->ip));
  packet->ip.ip_v = 4;
  packet->ip.ip_hl = sizeof(packet->ip) >> 2;
  packet->ip.ip_dst = *((struct in_addr*)(&destinationIp));
  packet->ip.ip_src = *((struct in_addr*)(&sourceIp));
  packet->ip.ip_p = kUdpProtocol;  // UDP protocol
  packet->ip.ip_ttl = ttl;

  int32_t packetExpectedSize = 128;

  // packet-size encode 6-bit: 5-bit TTL and 1 bit for encoding protoType.
  packetExpectedSize =
      packetExpectedSize | (ttl & 0x1F) | ((probePhaseCode_ & 0x1) << 5);

  // In OSX, please use: packet->ip.ip_len = packetExpectedSize;
  // Otherwise, you will have an Errno-22.
#if defined(__APPLE__) || defined(__MACH__)
  packet->ip.ip_len = packetExpectedSize;
  packet->ip.ip_id = kDefaultIPID;
#else
  packet->ip.ip_len = htons(packetExpectedSize);
  packet->ip.ip_id = htons(kDefaultIPID);
#endif

  memset(&packet->udp, '\0', sizeof(packet->udp));
  memcpy(packet->payload, payloadMessage_.c_str(), payloadMessage_.size());

#ifdef __FAVOR_BSD
  packet->udp.uh_dport = destinationPort_;
  packet->udp.uh_sport =
      getChecksum((uint16_t*)(&destinationIp), checksumOffset_);
  packet->udp.uh_ulen = htons(packetExpectedSize - sizeof(packet->ip));

  // if you set a checksum to zero, your kernel's IP stack should fill in
  // the correct checksum during transmission
  // packet->udp.uh_sum = 0;
  packet->udp.uh_sum =
      getChecksum(kUdpProtocol, packetExpectedSize - sizeof(packet->ip),
                  (uint16_t*)(&sourceIp), (uint16_t*)(&destinationIp),
                  (uint16_t*)(packetBuffer + sizeof(struct ip)));
#else
  packet->udp.dest = destinationPort_;
  packet->udp.source = getChecksum((uint16_t*)(packetBuffer));
  packet->udp.len = htons(packetExpectedSize - sizeof(packet->ip));

  // if you set a checksum to zero, your kernel's IP stack should fill in
  // the correct checksum during transmission
  // packet->udp.uh_sum = 0;
  packet->udp.check =
      getChecksum(kUdpProtocol, packetExpectedSize - sizeof(packet->ip),
                  (uint16_t*)(&sourceIp), (uint16_t*)(&destinationIp),
                  (uint16_t*)(packetBuffer + sizeof(struct ip)));
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

#ifdef __FAVOR_BSD

  if (getChecksum(reinterpret_cast<uint16_t*>(buffer + 28)) !=
      residualUdpPacket->udp.uh_sport) {
    // Checksum unmatched.
    checksumMismatches_ += 1;
    return;
  }
#else
  if (getChecksum(reinterpret_cast<uint16_t*>(buffer + 28)) !=
      residualUdpPacket->udp.source) {
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

  if (distance <= 0 || distance > kMaxTtl) {
    distanceAbnormalities_ += 1;
    return;
  }
#ifdef __FAVOR_BSD
  (*callback_)(destination, responder, static_cast<uint8_t>(distance),
               fromDestination, rtt, probePhase, replyIpId,
               parsedPacket->ip.ip_ttl, replyIpLen, probeIpLen, probeIpId,
               ntohs(residualUdpPacket->udp.uh_sport),
               ntohs(residualUdpPacket->udp.uh_dport));
#else
  (*callback_)(destination, responder, static_cast<uint8_t>(distance),
               fromDestination, rtt, probePhase, replyIpId,
               parsedPacket->ip.ip_ttl, replyIpLen, probeIpLen, probeIpId,
               ntohs(residualUdpPacket->udp.source),
               ntohs(residualUdpPacket->udp.dest));
#endif
}

uint16_t UdpIdempotentProber::getChecksum(const uint16_t* ipAddress,
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

uint16_t UdpIdempotentProber::getChecksum(uint16_t* buff) const {
  uint32_t sum = 0;

  /*
   * calculate the checksum for the tcp header and payload
   * len_tcp represents number of 8-bit bytes,
   * we are working with 16-bit words so divide len_tcp by 2.
   */
  for (uint32_t i = 0; i < 10; i++) {
    if (i != 4) {
      sum += buff[i];
    } else {
      sum += buff[i] & 0xFF00;
    }
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

uint64_t UdpIdempotentProber::getChecksummismatches() {
  return checksumMismatches_;
}

uint64_t UdpIdempotentProber::getDistanceAbnormalities() {
  return distanceAbnormalities_;
}

}  // namespace flashroute
