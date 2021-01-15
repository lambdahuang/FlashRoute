/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#include "flashroute/single_host.h"

#include <memory>
#include <string>

#include <boost/format.hpp>
#include "glog/logging.h"

#include "flashroute/utils.h"
#include "flashroute/udp_prober.h"
#include "flashroute/udp_prober_v6.h"

namespace flashroute {

SingleHost::SingleHost(const uint16_t srcPort, const uint16_t dstPort,
                       const uint8_t ttlOffset)
    : srcPort_(srcPort), dstPort_(dstPort), ttlOffset_(ttlOffset) {
  results_ = new std::unordered_map<
      uint8_t, std::tuple<std::shared_ptr<IpAddress>, uint32_t>>();
}

SingleHost::~SingleHost() {
  delete results_;
}

void SingleHost::startScan(const std::string& target,
                           const std::string& interface) {
  auto remoteHost =
      std::unique_ptr<IpAddress>(parseIpFromStringToIpAddress(target));

  std::string localIpAddress =
      getAddressByInterface(interface, remoteHost->isIpv4());


  PacketReceiverCallback response_handler =
      [this](const IpAddress& destination, const IpAddress& responder,
             uint8_t distance, uint32_t rtt, bool fromDestination, bool ipv4,
             void* packetBuffer, uint32_t packetLen) {
        parseIcmpProbing(destination, responder, distance, rtt, fromDestination,
                         ipv4, packetBuffer, packetLen);
      };

  Prober* prober;
  if (remoteHost->isIpv4()) {
    prober = new UdpProber(&response_handler, 0, 0, dstPort_, "test", true,
                           ttlOffset_);
  } else {
    prober = new UdpProberIpv6(&response_handler, 0, 0, dstPort_, "test");
  }
  NetworkManager networkManager(prober, interface, 100, remoteHost->isIpv4());
  networkManager.startListening();

  for (uint8_t i = 1; i <= 32; i ++) {
    networkManager.schedualProbeRemoteHost(*remoteHost, i);
  }

  sleep(3);

  for (uint8_t i = 1 + ttlOffset_; i <= 32 + ttlOffset_; i++) {
    if (results_->find(i) == results_->end()) {
      LOG(INFO) << boost::format("%1% %|5t|*") % static_cast<int>(i);
    } else {
      LOG(INFO) << boost::format("%1% %|5t|%2% %|5t|%3% ms") %
                       static_cast<int>(i) %
                       parseIpFromIpAddressToString(
                           *std::get<0>(results_->find(i)->second)) %
                       std::get<1>(results_->find(i)->second);
    }
  }

  LOG(INFO) << " =============================";

  LOG(INFO) << "Checksum Mismatches: " << prober->getChecksumMismatches();
  LOG(INFO) << "Distance Abnormalities: " << prober->getDistanceAbnormalities();
  LOG(INFO) << "Other Mismatches: " << prober->getOtherMismatches();
}

bool SingleHost::parseIcmpProbing(const IpAddress& destination,
                                  const IpAddress& responder, uint8_t distance,
                                  uint32_t rtt, bool fromDestination, bool ipv4,
                                  void* packetBuffer, uint32_t packetLen) {
  results_->insert(
      {distance,
       std::make_tuple(std::shared_ptr<IpAddress>(responder.clone()), rtt)});
  return true;
}

}  // namespace flashroute
