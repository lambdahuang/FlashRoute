#include "network.h"

#include <chrono>

#include "glog/logging.h"

#include <iostream>

#include <boost/asio.hpp>
#include <boost/circular_buffer.hpp>
#include "flashroute/utils.h"
#include "flashroute/bounded_buffer.h"
#include "flashroute/prober.h"

namespace flashroute {

const uint16_t kPacketBufferSize = 2048;  // Default sending buffer size which
                                          // will be used to generate packets.
const uint16_t kReceivingBufferSize =
    2000;  // Default receiving buffer size which will be used to store received
           // packets.
const uint32_t kThreadPoolSize = 3;  // Default thread pool size.

NetworkManager::NetworkManager(Prober* prober, const std::string& interface,
                               const uint64_t sendingRate)
    : prober_(prober),
      stopReceiving_(false),
      expectedRate_(static_cast<double>(sendingRate)),
      sentPackets_(0),
      receivedPackets_(0) {
  createRawSocket();

  if (!interface.empty()) {
    localIpAddress_ = std::unique_ptr<IpAddress>(
        parseIpFromStringToIpAddress(getAddressByInterface(interface)));
  } else {
    LOG(FATAL) << "Network Module: Local address is not configured.";
  }

  threadPool_ = std::make_unique<boost::asio::thread_pool>(kThreadPoolSize);

  // Initialize sending buffer
  sendingBuffer_ =
      std::make_unique<BoundedBuffer<ProbeUnitIpv4>>(expectedRate_);

  // Initialize sending thread. Sending thread is to drain the sending buffer
  // and put the packet on wire.
  boost::asio::post(*threadPool_.get(), [this]() { runSendingThread(); });

  if (expectedRate_ < 1) {
    VLOG(2) << "Network Module: Sendg rate limit is disabled since expected "
               "rate is "
            << expectedRate_;
  }
}

void NetworkManager::resetProber(Prober* prober) {
  prober_ = prober;
}

void NetworkManager::probeRemoteHost(const IpAddress& destinationIp,
                                     const uint8_t ttl) {
  static uint8_t buffer[kPacketBufferSize];
  size_t packetSize =
      prober_->packProbe(destinationIp, *localIpAddress_, ttl, buffer);

  sendRawPacket(buffer, packetSize);
}

void NetworkManager::schedualProbeRemoteHost(const IpAddress& destinationIp,
                                             const uint8_t ttl) {
  if (expectedRate_ >= 1) {
    if (destinationIp.isIpv4()) {
      ProbeUnitIpv4 tmp(dynamic_cast<const Ipv4Address&>(destinationIp), ttl);
      sendingBuffer_->pushFront(tmp);
    } else {
      // TODO(neohuang): handle IPv6.
    }
  } else {
    // if we disable rate limit.
    probeRemoteHost(destinationIp, ttl);
  }
}

void NetworkManager::startListening() {
  createIcmpSocket();
  boost::asio::post(*threadPool_.get(), [this]() { receiveIcmpPacket(); });
  VLOG(2) << "Network Module: Start capturing incoming ICMP packets.";
}

void NetworkManager::stopListening() {
  if (mainReceivingSocket_ != 0) {
    shutdown(mainReceivingSocket_, SHUT_RDWR);
    close(mainReceivingSocket_);
  }
  {
    std::lock_guard<std::mutex> guard(stopReceivingMutex_);
    stopReceiving_ = true;
  }
  threadPool_->join();
  VLOG(2) << "Network Module: All working threads are recycled.";
}

bool NetworkManager::createIcmpSocket() {
  // create raw socket return -1 if failed
  mainReceivingSocket_ = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  int on = 1;
  if (mainReceivingSocket_ < 0 ||
      setsockopt(mainReceivingSocket_, IPPROTO_IP, IP_HDRINCL,
                 reinterpret_cast<char*>(&on), sizeof(on)) < 0) {
    LOG(FATAL)
        << "Network Module: Raw ICMP receiving socket failed to initialize.";
    return false;
  }

  int optval = 0;
  int socklen = sizeof(optval);
  int bufsize = 400 * 1024;
  if (getsockopt(mainReceivingSocket_, SOL_SOCKET, SO_RCVBUF,
                 reinterpret_cast<char*>(&optval),
                 reinterpret_cast<socklen_t*>(&socklen)) < 0) {
    VLOG(2) << "Network Module: Failed to get receiving buffer size.";
  } else {
    VLOG(2) << "Network Module: Receiving buffer size is " << optval;
  }
  if (setsockopt(mainReceivingSocket_, SOL_SOCKET, SO_RCVBUF, &bufsize,
                 sizeof(bufsize)) < 0) {
    VLOG(2) << "Network Module: Failed to set receiving buffer size.";
  } else {
    VLOG(2) << "Network Module: Receiving buffer has been set to " << bufsize;
  }
  VLOG(2) << "Network Module: Raw ICMP receiving socket initialized.";
  return true;
}

bool NetworkManager::createRawSocket() {
  // create raw socket return -1 if failed
  sendingSocket_ = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  int on = 1;
  if (sendingSocket_ < 0 ||
      setsockopt(sendingSocket_, IPPROTO_IP, IP_HDRINCL,
                 reinterpret_cast<char*>(&on), sizeof(on)) < 0) {
    LOG(FATAL) << "The sending socket initialize failed.";
    return false;
  }
  VLOG(2) << "Network Module: Raw sending socket initialized.";
  return true;
}

void NetworkManager::runSendingThread() {
  if (expectedRate_ < 1) {
    VLOG(2) << "Network module: sending thread disabled.";
  }
  VLOG(2) << "Network module: Sending thread initialized.";
  ProbeUnitIpv4 tmp;

  uint64_t sentProbes = 0;
  auto lastSeenTimestamp = std::chrono::steady_clock::now();
  while (!isStopReceiving()) {
    if (sendingBuffer_->empty()) {
      continue;
    }
    double timeDifference =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - lastSeenTimestamp)
            .count();
    if (timeDifference >= 1000) {
      sentProbes = 0;
      lastSeenTimestamp = std::chrono::steady_clock::now();
    }
    if (sentProbes >= expectedRate_) {
      continue;
    }
    sendingBuffer_->popBack(&tmp);
    probeRemoteHost(tmp.ip, tmp.ttl);
    sentProbes += 1;
  }
  VLOG(2) << "Network module: Sending thread recycled.";
}

void NetworkManager::receiveIcmpPacket() {
  VLOG(2) << "Network module: Receiving thread initialized.";
  uint8_t buffer[kReceivingBufferSize];
  while (!isStopReceiving()) {
    int32_t packetSize = recv(mainReceivingSocket_, &buffer, sizeof(buffer), 0);
    // an icmp packet has to have an 8-byte ip header and a 20-byte icmp
    // header
    if (packetSize < 28) {
      continue;
    }

    {
      std::lock_guard<std::mutex> guard(receivedPacketMutex_);
      receivedPackets_ += 1;
    }
    prober_->parseResponse(buffer, packetSize, SocketType::ICMP);
  }
  VLOG(2) << "Network module: Receiving thread recycled.";
}

void NetworkManager::sendRawPacket(uint8_t* buffer, size_t length) {
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_port = 80;
  sin.sin_addr.s_addr = 1;
  if (sendto(sendingSocket_, buffer, length, 0, (struct sockaddr*)&sin,
             sizeof(sin)) < 0) {
    LOG(ERROR) << "Send packet failed. Errno: " << errno;
  } else {
    std::lock_guard<std::mutex> guard(sentPacketsMutex_);
    sentPackets_ += 1;
  }
}

uint64_t NetworkManager::getSentPacketCount() {
  std::lock_guard<std::mutex> guard(sentPacketsMutex_);
  return sentPackets_;
}

uint64_t NetworkManager::getReceivedPacketCount() {
  std::lock_guard<std::mutex> guard(receivedPacketMutex_);
  return receivedPackets_;
}

bool NetworkManager::isStopReceiving() {
  std::lock_guard<std::mutex> guard(stopReceivingMutex_);
  return stopReceiving_;
}

}  // namespace flashroute
