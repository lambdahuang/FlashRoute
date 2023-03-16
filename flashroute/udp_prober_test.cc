/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#include "gtest/gtest.h"

#include "flashroute/prober.h"
#include "flashroute/udp_prober.h"

using namespace flashroute;

const uint16_t kTestBufferSize = 512;

TEST(UdpProber, PackProbeTest) {
  Ipv4Address destinationIp{12456};
  Ipv4Address sourceIp{6789};
  uint8_t initialTtl = 17;
  PacketReceiverCallback response_handler =
      [](const IpAddress& destination, const IpAddress& responder,
         uint8_t distance, uint32_t rtt, bool fromDestination, bool ipv4,
         void* packetHeader, size_t headerLen) {};

  UdpProber prober(&response_handler, 0, 1, 0, "test", true, 0);

  uint8_t buffer[kTestBufferSize];
  size_t size = prober.packProbe(destinationIp, sourceIp, initialTtl, buffer);
  prober.parseResponse(buffer, size, SocketType::ICMP);

#if defined(__APPLE__) || defined(__MACH__)
  uint16_t packetIPID = *(reinterpret_cast<uint16_t*>(buffer+4));
#else
  uint16_t packetIPID = ntohs(*(reinterpret_cast<uint16_t*>(buffer+4)));
#endif
  uint8_t packetTtl = *(reinterpret_cast<uint8_t*>(buffer+8));
  uint32_t packetSourceIp = *(reinterpret_cast<uint32_t*>(buffer+12));
  uint32_t packetDestinationIp = *(reinterpret_cast<uint32_t*>(buffer+16));
  uint8_t probePhase = (packetIPID >> 5) & 1;

  EXPECT_EQ((packetIPID & 0x1F), 17);
  EXPECT_EQ(packetTtl, 17);
  EXPECT_EQ(packetSourceIp, htonl(sourceIp.getIpv4Address()));
  EXPECT_EQ(packetDestinationIp, htonl(destinationIp.getIpv4Address()));
  EXPECT_EQ(probePhase, 1);
}
