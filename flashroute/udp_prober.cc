#include <memory>
#include <cstring>

#include <netinet/ip.h>       // ip header
#include <netinet/ip_icmp.h>  // icmp header
#include <netinet/tcp.h>
#include <netinet/udp.h>  // udp header

#include "glog/logging.h"
#include "flashroute/udp_prober.h"

namespace flashroute {

const uint8_t kUdpProtocol = 17;  // Default UDP protocol id.

// The maximum ttl we will explore.
const uint8_t kMaxTtl = 32;

UdpProber::UdpProber(PacketReceiverCallback* callback,
                     const int32_t checksumOffset, const uint8_t probePhaseCode,
                     const uint16_t destinationPort,
                     const std::string& payloadMessage) {
  probePhaseCode_ = probePhaseCode;
  callback_ = callback;
  checksumOffset_ = checksumOffset;
  payloadMessage_ = payloadMessage;
  destinationPort_ = htons(destinationPort);
  checksumMismatches = 0;
  distanceAbnormalities = 0;
}

size_t UdpProber::packProbe(const uint32_t destinationIp,
                            const uint32_t sourceIp, const uint8_t ttl,
                            uint8_t* packetBuffer) {
  struct PacketUdp* packet =
      reinterpret_cast<struct PacketUdp*>(packetBuffer);

  uint16_t timestamp = getTimestamp();
  // Fabricate the IP header or we can use the
  // standard header structures but assign our own values.
  memset(&packet->ip, 0, sizeof(packet->ip));
  packet->ip.ip_v = 4;
  packet->ip.ip_hl = sizeof(packet->ip) >> 2;
  packet->ip.ip_dst = *((struct in_addr*)(&destinationIp));
  packet->ip.ip_src = *((struct in_addr*)(&sourceIp));
  packet->ip.ip_p = kUdpProtocol;  // UDP protocol
  packet->ip.ip_ttl = ttl;
  // ipid: 5-bit for intiial TTL, 1 bit for probeType, 10-bit for timestamp
  // reuse ip id for storing the orignal ttl
  // 0x3FF = 2^10 to extract first 10-bit of timestamp
  uint16_t ipid = (ttl & 0x1F) | ((probePhaseCode_ & 0x1) << 5) |
                     ((timestamp & 0x3FF) << 6);

  // packet-size encode 6-bit timestamp
  // (((timestamp >> 10) & 0x3F) << 6): the rest 6-bit of time stamp
  int32_t packet_expect_size = 128 + (((timestamp >> 10) & 0x3F) << 1);
  // In OSX, please use: packet->ip.ip_len = packet_expect_size;
  // Otherwise, you will have an Errno-22.
#if defined(__APPLE__) || defined(__MACH__)
  packet->ip.ip_len = packet_expect_size;
  packet->ip.ip_id = ipid;
#else
  packet->ip.ip_len = htons(packet_expect_size);
  packet->ip.ip_id = htons(ipid);
#endif


  memset(&packet->udp, '\0', sizeof(packet->udp));
  packet->udp.uh_dport = destinationPort_;
  packet->udp.uh_sport =
      getChecksum((uint16_t*)(&destinationIp), checksumOffset_);
  packet->udp.uh_ulen = htons(packet_expect_size - sizeof(packet->ip));
  // htons(message.size() + sizeof(packet->udp));

  memcpy(packet->payload, payloadMessage_.c_str(), payloadMessage_.size());
  // if you set a checksum to zero, your kernel's IP stack should fill in
  // the correct checksum during transmission
  // packet->udp.uh_sum = 0;
  packet->udp.uh_sum =
      getChecksum(kUdpProtocol, packet_expect_size - sizeof(packet->ip),
                  (uint16_t*)(&sourceIp), (uint16_t*)(&destinationIp),
                  (uint16_t*)(packetBuffer + sizeof(struct ip)));

  return packet_expect_size;
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
  if (getChecksum(
          reinterpret_cast<uint16_t*>(&residualUdpPacket->ip.ip_dst.s_addr),
          checksumOffset_) != residualUdpPacket->udp.uh_sport) {
    // Checksum unmatched.
    checksumMismatches += 1;
    return;
  }
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
    distanceAbnormalities += 1;
    return;
  }
  (*callback_)(destination, responder, static_cast<uint8_t>(distance),
               fromDestination, rtt, probePhase, replyIpId,
               parsedPacket->ip.ip_ttl, replyIpLen, probeIpLen, probeIpId,
               ntohs(residualUdpPacket->udp.uh_sport),
               ntohs(residualUdpPacket->udp.uh_dport));
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

}  // namespace flashroute
