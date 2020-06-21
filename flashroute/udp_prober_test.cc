/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#include "gtest/gtest.h"

#include "flashroute/prober.h"
#include "flashroute/udp_prober.h"

using namespace flashroute;

const uint16_t kTestBufferSize = 512;

TEST(UdpProber, PackProbeTest) {
  uint32_t destinationIp = 12456;
  uint32_t sourceIp = 6789;
  uint8_t initialTtl = 17;
  PacketReceiverCallback response_handler =
      [](uint32_t destination, uint32_t responder, uint8_t distance,
         bool fromDestination, uint32_t rtt, uint8_t probePhase,
         uint16_t replyIpid, uint8_t replyTtl, uint32_t replySize,
         uint32_t probeSize, uint16_t probeIpid, uint16_t probeSourcePort,
         uint16_t probeDestinationPort) {};

  UdpProber prober(&response_handler, 0, 1, 0, "test");

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
  EXPECT_EQ(packetSourceIp, sourceIp);
  EXPECT_EQ(packetDestinationIp, destinationIp);
  EXPECT_EQ(probePhase, 1);
}
