/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#pragma once


#include <sys/socket.h>

#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include "flashroute/address.h"
#include <boost/asio/thread_pool.hpp>
#include "flashroute/bounded_buffer.h"
#include "flashroute/prober.h"

namespace flashroute {

class ProbeUnitIpv4 {
 public:
  Ipv4Address ip;
  uint8_t ttl;
  ProbeUnitIpv4() : ip(0), ttl(0) {}
  ProbeUnitIpv4(const Ipv4Address& _ip, const uint8_t _ttl)
      : ip(_ip), ttl(_ttl) {}
};

/**
 * Network manager handles sending and receiving packets.
 *
 * Example:
 *
 * PacketReceiverCallback callback =
 *    [](uint32_t destination, uint32_t responder,
 *                    uint8_t distance, bool fromDestination) {
 *      // The tracerouting logic on response.
 *    };
 *
 * UdpProber prober(...);
 *
 * NetworkManager networkManager(
 *  &prober,  // The prober to process packets.
 *  "eth0",   // The interface to send the probe.
 *  100000    // The packet sending rate.
 * );
 *
 * // Start capturing the incoming packets.
 * networkManager.startListening();
 *
 * // Stop capturing;
 * networkManager.stopListening();
 *
 * // Print the number of sent packet.
 * LOG(INFO) << networkManager.getSentPacketCount();
 *
 * // Print the number of received packet.
 * LOG(INFO) << networkManager.getReceivedPacketCount();
 *
 */

class NetworkManager {
 public:
  NetworkManager(Prober* prober, const std::string& interface,
                 const uint64_t sendingRate);
  // Scheduale to send a probe. Sending accords to the pre-determined sending
  // rate.
  void schedualProbeRemoteHost(const IpAddress& destinationIp,
                               const uint8_t ttl);

  // Start capturing the packets.
  void startListening();

  // Stop capturing the packets.
  void stopListening();

  // Return the statistics of sent/received packets.
  uint64_t getSentPacketCount();

  uint64_t getReceivedPacketCount();

 private:
  Prober* prober_;
  std::unique_ptr<IpAddress> localIpAddress_;
  uint16_t srcPort_;
  uint16_t dstPort_;

  // The socket to receive Icmp packets
  int mainReceivingSocket_;

  // Message embedded in each probe
  std::string packetPayloadMessage_;

  int sendingSocket_;

  // Thread pool
  std::unique_ptr<boost::asio::thread_pool> threadPool_;

  bool stopReceiving_;
  std::mutex stopReceivingMutex_;

  // Sending buffer
  std::unique_ptr<BoundedBuffer<ProbeUnitIpv4>> sendingBuffer_;

  // Rate control
  double expectedRate_;

  // Statistic
  uint64_t sentPackets_;
  std::mutex sentPacketsMutex_;
  uint64_t receivedPackets_;
  std::mutex receivedPacketMutex_;

  bool createIcmpSocket();

  bool createRawSocket();

  void runSendingThread();

  // Send the probe immediately.
  void probeRemoteHost(const IpAddress& destinationIp, const uint8_t ttl);

  void receiveIcmpPacket();

  void sendRawPacket(uint8_t* buffer, size_t len);

  bool isStopReceiving();
};

}  // namespace flashroute
