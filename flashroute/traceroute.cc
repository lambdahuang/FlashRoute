/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#include "flashroute/traceroute.h"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <thread>
#include <utility>

#include "absl/strings/numbers.h"
#include "absl/strings/string_view.h"
#include <boost/asio.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/format.hpp>
#include "glog/logging.h"

#include "flashroute/dcb.h"
#include "flashroute/utils.h"
#include "flashroute/network.h"
#include "flashroute/prober.h"
#include "flashroute/udp_prober.h"
#include "flashroute/udp_prober_v6.h"
#include "flashroute/udp_idempotent_prober.h"

namespace flashroute {

// the bit-length of the mask of ip address block, for example, for
// /24 ip address block, the corresponding value is 24
const uint8_t kProbingGranularity = 24;

const uint32_t kDiscoverySetCapacity = 100;

const uint32_t kThreadPoolSize = 2;

const uint32_t kStatisticCalculationIntervalMs = 5000;

// Probing Mark 1-bit
const uint8_t kMainProbePhase = 0x1;
const uint8_t kPreProbePhase = 0x0;

// The maximum ttl we will explore.
const uint8_t kMaxTtl = 32;

// After sending all preprobes, there might be some response on
// the way back to our host, we use kHaltTimeAfterPreprobingSequenceMs
// to control how long we need to wait for those inflight response.
const uint32_t kHaltTimeAfterPreprobingSequenceMs = 3000;

Tracerouter::Tracerouter(
    DcbManager* dcbManager, NetworkManager* networkManager,
    ResultDumper* resultDumper, NonstopSet* nonstopSet, const uint8_t defaultSplitTTL,
    const uint8_t defaultPreprobingTTL, const bool forwardProbing,
    const uint8_t forwardProbingGapLimit, const bool redundancyRemoval,
    const bool preprobing, const bool preprobingPrediction,
    const int32_t predictionProximitySpan, const int32_t scanCount,
    const uint16_t srcPort, const uint16_t dstPort,
    const std::string& defaultPayloadMessage, const bool encodeTimestamp,
    const uint8_t ttlOffset, bool randomizeAddressinExtraScans)
    : dcbManager_(dcbManager),
      stopProbing_(false),
      probePhase_(ProbePhase::NONE),
      resultDumper_(resultDumper),
      networkManager_(networkManager),
      nonstopSet_(nonstopSet),
      defaultSplitTTL_(defaultSplitTTL),
      defaultPreprobingTTL_(defaultPreprobingTTL),
      ttlOffset_(ttlOffset),
      forwardProbingMark_(forwardProbing),
      forwardProbingGapLimit_(forwardProbingGapLimit),
      redundancyRemovalMark_(redundancyRemoval),
      preprobingMark_(preprobing),
      preprobingPredictionMark_(preprobingPrediction),
      preprobingPredictionProximitySpan_(predictionProximitySpan),
      scanCount_(scanCount),
      randomizeAddressInExtraScans_(randomizeAddressinExtraScans),
      sentPreprobes_(0),
      preprobeUpdatedCount_(0),
      sentProbes_(0),
      receivedResponses_(0),
      stopMonitoringMark_(false),
      probingIterationRounds_(0),
      srcPort_(srcPort),
      dstPort_(dstPort),
      defaultPayloadMessage_(defaultPayloadMessage),
      encodeTimestamp_(encodeTimestamp) {
  // Thread pool for handling different purposes.
  threadPool_ = std::make_unique<boost::asio::thread_pool>(kThreadPoolSize);

  // initialize the data structure to remember visited interfaces;
  backwardProbingStopSet_.reserve(kDiscoverySetCapacity);
  forwardProbingDiscoverySet_.reserve(kDiscoverySetCapacity);
}

Tracerouter::~Tracerouter() {
  stopMonitoringMark_ = true;
  if (threadPool_.get() != nullptr) {
    threadPool_->join();
    threadPool_.release();
  }
  VLOG(2) << "Traceroute Module: Tracerouter is recycled.";
}

void Tracerouter::startMetricMonitoring() {
  VLOG(2) << "Traceroute Module: Monitoring thread initialized.";
  stopMonitoringMark_ = false;
  boost::asio::post(*threadPool_.get(), [this]() {
    auto lastSeenTimestamp = std::chrono::steady_clock::now();
    uint64_t lastSeenSentPackets = 0;
    uint64_t lastSeenReceivedPackets = 0;

    while (!stopMonitoringMark_ && !stopProbing_) {
      if (networkManager_ != nullptr) {
        uint64_t shadowSentPacket = networkManager_->getSentPacketCount();
        uint64_t shadowReceivedPacket =
            networkManager_->getReceivedPacketCount();

        double timeDifference =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - lastSeenTimestamp)
                .count();
        double sendingSpeed =
            static_cast<double>(shadowSentPacket - lastSeenSentPackets) /
            timeDifference * 1000;

        double receivingSpeed = static_cast<double>(shadowReceivedPacket -
                                                    lastSeenReceivedPackets) /
                                timeDifference * 1000;

        double preprobeUpdatedProportion =
            static_cast<double>(preprobeUpdatedCount_) / sentPreprobes_ * 100;

        double remainingBlockProportion =
            static_cast<double>(dcbManager_->liveDcbSize()) /
            dcbManager_->size() * 100;
        if (lastSeenSentPackets != 0 && lastSeenReceivedPackets != 0) {
          LOG(INFO) << boost::format(
                           "R: %d S: %5.2fk R: %5.2fk PreP: %5.2f RmnP: %5.2f "
                           "IfCnt: %d FwIfCnt: %d") %
                           probingIterationRounds_ % (sendingSpeed / 1000) %
                           (receivingSpeed / 1000) % preprobeUpdatedProportion %
                           remainingBlockProportion %
                           backwardProbingStopSet_.size() %
                           forwardProbingDiscoverySet_.size();
        }

        lastSeenSentPackets = shadowSentPacket;
        lastSeenReceivedPackets = shadowReceivedPacket;
        lastSeenTimestamp = std::chrono::steady_clock::now();
      } else {
        LOG(INFO) << "Temporary no metrics.";
      }
      std::this_thread::sleep_for(
          std::chrono::milliseconds(kStatisticCalculationIntervalMs));
    }
    VLOG(2) << "Traceroute Module: Monitoring thread recycled.";
  });
}

void Tracerouter::startScan(ProberType proberType, bool ipv4,
                            bool randomizeAddressAfterPreprobing) {
  stopProbing_ = false;
  checksumMismatches_ = 0;
  distanceAbnormalities_ = 0;
  droppedResponses_ = 0;
  auto startTimestamp = std::chrono::steady_clock::now();
  VLOG(2) << "There are " << dcbManager_->size() << " targets to probe.";

  startMetricMonitoring();
  if (preprobingMark_) {
    startPreprobing(proberType, ipv4);
    if (randomizeAddressAfterPreprobing) {
      dcbManager_->randomizeAddress();
    } else {
      if (defaultSplitTTL_ == defaultPreprobingTTL_) {
        // Folding the preprobing into main probing
        defaultSplitTTL_ -= 1;
        LOG(INFO) << "Main probing starts at TTL 31 since preprobin already "
                     "explores TTL 32.";
      }
    }
  }
  if (!stopProbing_) startProbing(proberType, ipv4);
  auto endTimestamp = std::chrono::steady_clock::now();
  stopProbing_ = true;
  stopMetricMonitoring();

  uint64_t elapsedTimeMs =
      std::chrono::duration_cast<std::chrono::milliseconds>(endTimestamp -
                                                            startTimestamp)
          .count();
  calculateStatistic(elapsedTimeMs);
  return;
}

void Tracerouter::stopMetricMonitoring() {
  stopMonitoringMark_ = true;
  std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

void Tracerouter::startPreprobing(ProberType proberType, bool ipv4) {
  // Update status.
  probePhase_ = ProbePhase::PREPROBE;
  // Set up callback function.
  PacketReceiverCallback callback =
      [this](const IpAddress& destination, const IpAddress& responder,
             uint8_t distance, uint32_t rtt, bool fromDestination, bool ipv4,
             void* receivedPacket, size_t packetLen) {
        if (parseIcmpPreprobing(destination, responder, distance,
                                fromDestination) &&
            resultDumper_ != nullptr) {
          resultDumper_->scheduleDumpData(destination, responder, distance, rtt,
                                          fromDestination, ipv4, receivedPacket,
                                          packetLen);
        }
      };

  if (proberType == ProberType::UDP_PROBER) {
    if (ipv4) {
      prober_ = std::make_unique<UdpProber>(&callback, 0, kPreProbePhase,
                                            dstPort_, defaultPayloadMessage_,
                                            encodeTimestamp_, ttlOffset_);
    } else {
      prober_ = std::make_unique<UdpProberIpv6>(
          &callback, 0, kPreProbePhase, dstPort_, defaultPayloadMessage_,
          ttlOffset_);
    }
  } else if (proberType == ProberType::UDP_IDEMPOTENT_PROBER) {
    prober_ = std::make_unique<UdpIdempotentProber>(
        &callback, 0, kPreProbePhase, dstPort_, defaultPayloadMessage_,
        encodeTimestamp_, ttlOffset_);
  } else {
    LOG(FATAL) << "Error in creating prober.";
  }

  // Set network manager
  networkManager_->resetProber(prober_.get());
  networkManager_->startListening();

  auto startTimestamp = std::chrono::steady_clock::now();
  LOG(INFO) << "Start preprobing.";
  uint64_t dcbCount = dcbManager_->liveDcbSize();
  for (uint64_t i = 0; i < dcbCount && !stopProbing_; i++) {
    networkManager_->scheduleProbeRemoteHost(*(dcbManager_->next()->ipAddress),
                                           defaultPreprobingTTL_);
  }
  std::this_thread::sleep_for(
      std::chrono::milliseconds(kHaltTimeAfterPreprobingSequenceMs));

  networkManager_->stopListening();

  int64_t timeDifference =
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::steady_clock::now() - startTimestamp)
          .count();
  LOG(INFO) << boost::format("Preprobing finished (Took %d seconds).") %
                   timeDifference;

  sentPreprobes_ = networkManager_->getSentPacketCount();
}

void Tracerouter::startProbing(ProberType proberType, bool ipv4) {
  // Update status
  probePhase_ = ProbePhase::PROBE;
  // Set up callback function.
  PacketReceiverCallback callback =
      [this](const IpAddress& destination, const IpAddress& responder,
             uint8_t distance, uint32_t rtt, bool fromDestination, bool ipv4,
             void* receivedPacket, size_t packetLen) {
        if (parseIcmpProbing(destination, responder, distance,
                             fromDestination) &&
            resultDumper_ != nullptr) {
          resultDumper_->scheduleDumpData(destination, responder, distance, rtt,
                                          fromDestination, ipv4, receivedPacket,
                                          packetLen);
        }
      };

  if (proberType == ProberType::UDP_PROBER) {
    if (ipv4) {
      prober_ = std::make_unique<UdpProber>(&callback, 0, kMainProbePhase,
                                            dstPort_, defaultPayloadMessage_,
                                            encodeTimestamp_, ttlOffset_);

    } else {
      prober_ = std::make_unique<UdpProberIpv6>(
          &callback, 0, kPreProbePhase, dstPort_, defaultPayloadMessage_,
          ttlOffset_);
    }
  } else if (proberType == ProberType::UDP_IDEMPOTENT_PROBER) {
    prober_ = std::make_unique<UdpIdempotentProber>(
        &callback, 0, kMainProbePhase, dstPort_, defaultPayloadMessage_,
        encodeTimestamp_, ttlOffset_);
  } else {
    LOG(FATAL) << "Error in creating prober.";
  }

  networkManager_->resetProber(prober_.get());
  networkManager_->startListening();
  auto startTimestamp = std::chrono::steady_clock::now();
  auto lastRoundTimestamp = std::chrono::steady_clock::now();

  // Take a snapshot for DCBs' links.
  if (scanCount_ > 1) {
    dcbManager_->snapshot();
  }

  LOG(INFO) << "Start main probing.";
  int32_t scanRound  = -1;
  for (int scanCount = 0; scanCount < scanCount_ && !stopProbing_;
       scanCount++) {
    if (scanCount > 0) {
      LOG(INFO) << "< ===========";
      LOG(INFO) << scanCount
                << " extra round of main probing. Destination port offset "
                << scanCount;
      dcbManager_->reset();
      if (randomizeAddressInExtraScans_) {
        LOG(INFO) << "Randomize addresses for the coming scan.";
        dcbManager_->shuffleAddress();
      }
      probingIterationRounds_ = 0;
      prober_->setChecksumOffset(scanCount);
    }
    // send probes to all targeting blocks
    do {
      if (dcbManager_->scanRound > scanRound) {
        probingIterationRounds_ += 1;
        // Sleep one second if the delta is less than one second.
        int32_t delta =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - lastRoundTimestamp)
                .count();
        if (delta < 1000) {
          std::this_thread::sleep_for(std::chrono::milliseconds(1000 - delta));
        }
        lastRoundTimestamp = std::chrono::steady_clock::now();
        scanRound = dcbManager_->scanRound;
      }
      DestinationControlBlock& dcb = *dcbManager_->next();

      uint8_t nextForwardTask = dcb.pullForwardTask();
      uint8_t nextBackwardTask = dcb.pullBackwardTask(ttlOffset_);

      bool hasForwardTask = nextForwardTask != 0;
      bool hasBackwardTask = nextBackwardTask != 0;
      // An entry will be removed only if backward and forward probings are
      // all done.
      if (!hasBackwardTask &&
          (!forwardProbingMark_ || scanCount > 0 || !hasForwardTask)) {
        dcbManager_->removeDcbFromIteration(&dcb);
      } else {
        if (forwardProbingMark_ && hasForwardTask) {
          // forward probing
          networkManager_->scheduleProbeRemoteHost(
              *dcb.ipAddress, nextForwardTask);
        }
        if (hasBackwardTask) {
          // backward probing
          networkManager_->scheduleProbeRemoteHost(
              *dcb.ipAddress, nextBackwardTask);
        }
      }
    } while (!stopProbing_ && dcbManager_->hasNext());
    LOG(INFO) << "Scan finished.";
  }
  networkManager_->stopListening();
  int64_t timeDifference =
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::steady_clock::now() - startTimestamp)
          .count();
  LOG(INFO) << boost::format("Main probing finished (Took %d seconds).") %
                   timeDifference;

  // Update status
  probePhase_ = ProbePhase::NONE;
  sentProbes_ = networkManager_->getSentPacketCount();
  receivedResponses_ = networkManager_->getReceivedPacketCount();
  checksumMismatches_ = prober_->getChecksumMismatches();
  distanceAbnormalities_ = prober_->getDistanceAbnormalities();
  // Dropped responses for other reasons.
  droppedResponses_ += prober_->getOtherMismatches();
}

bool Tracerouter::parseIcmpPreprobing(const IpAddress& destination,
                                      const IpAddress& responder,
                                      uint8_t distance, bool fromDestination) {
  if (!fromDestination) {
    droppedResponses_++;
    return false;
  }

  DestinationControlBlock* dcb = dcbManager_->getDcbByAddress(destination);
  if (dcb == nullptr) {
    droppedResponses_++;
    return false;
  }

  // The preprobe should update the max ttl always shorter than the ttl of
  // preprobes, otherwise, the target host won't receive preprobe.
  if (dcb->updateSplitTtl(distance, true)) {
    preprobeUpdatedCount_ += 1;
  }
  if (preprobingPredictionMark_) {
    std::vector<DestinationControlBlock*>* result =
        dcbManager_->getDcbsByAddress(destination);
    if (result != nullptr) {
      for (auto it = result->begin(); it != result->end(); it++) {
        if ((*it)->updateSplitTtl(distance, false)) {
          preprobeUpdatedCount_++;
        }
      }
      // remove all dcbs from future update.
      result->clear();
    }
  }
  return true;
}

bool Tracerouter::parseIcmpProbing(const IpAddress& destination,
                                   const IpAddress& responder, uint8_t distance,
                                   bool fromDestination) {
  // Convert the target ip address to the corresponding block index.
  DestinationControlBlock* dcb = dcbManager_->getDcbByAddress(destination);
  if (dcb == nullptr) {
    std::vector<DestinationControlBlock*>* result =
        dcbManager_->getDcbsByAddress(destination);
    if (result != nullptr && result->size() == 1) {
      dcb = result->at(0);
    } else {
      droppedResponses_++;
      return false;
    }
  }
  if (!fromDestination) {
    // Time Exceeded
    if (dcb->initialBackwardProbingTtl < distance) {
      // The response is from forward probing / the distance is error if
      // forward probing is not activated.
      forwardProbingDiscoverySet_.insert(responder.clone());
    } else {
      // The response is from backward probing.
      if (backwardProbingStopSet_.find(&(const_cast<IpAddress&>(responder))) !=
          backwardProbingStopSet_.end()) {
        // We stop only for router interfaces discovered in backward
        // probing.
        if (redundancyRemovalMark_ || nonstopSet_ == nullptr ||
            !nonstopSet_->contains(&responder)) {
          static_cast<uint64_t>(dcb->stopBackwardProbing());
        }
      } else {
        // Only add address to stop set if it is not in nonstop set.
        backwardProbingStopSet_.insert(responder.clone());
      }
    }
    if (distance <= dcb->getMaxProbedDistance()) {
      // Set forward probing
      int16_t newMax = std::min<int16_t>(
          distance + static_cast<int16_t>(forwardProbingGapLimit_),
          kMaxTtl + ttlOffset_);
      if (newMax > 0 && newMax <= kMaxTtl + ttlOffset_) {
        dcb->setForwardHorizon(static_cast<uint8_t>(newMax));
      }
    }
  } else {
    dcb->stopForwardProbing();
  }
  return true;
}

void Tracerouter::calculateStatistic(uint64_t elapsedTime) {
  double averageSendingRate =
      static_cast<double>(sentProbes_ + sentPreprobes_) / elapsedTime;
  double averageReceivingRate =
      static_cast<double>(receivedResponses_) / elapsedTime;

  LOG(INFO) << boost::format("Average Sending Rate: %|30t|%.2f Kpps") %
                   averageSendingRate;
  LOG(INFO) << boost::format("Average Receving Rate: %|30t|%.2f Kpps") %
                   averageReceivingRate;
  LOG(INFO) << boost::format("Sent packets: %|30t|%ld") %
                   (sentProbes_ + sentPreprobes_);
  LOG(INFO) << boost::format("Received packets: %|30t|%ld") %
                   receivedResponses_;
  LOG(INFO) << boost::format("Total Dropped responses: %|30t|%ld") %
                   (checksumMismatches_ + distanceAbnormalities_ +
                    droppedResponses_);
  LOG(INFO) << boost::format("Other dropped: %|30t|%ld") %
                   (droppedResponses_);
  LOG(INFO) << boost::format("Checksum Mismatches: %|30t|%ld") %
                   (checksumMismatches_);
  LOG(INFO) << boost::format("Distance Abnormalities: %|30t|%ld") %
                   (distanceAbnormalities_);
  LOG(INFO) << boost::format("Sent probes: %|30t|%1%") % sentProbes_;
  LOG(INFO) << boost::format("Sent preprobes: %|30t|%ld") % sentPreprobes_;

  LOG(INFO) << boost::format("Interfaces Forward-probing: %|30t|%ld") %
                   forwardProbingDiscoverySet_.size();
  LOG(INFO) << boost::format("Interfaces Backward-probing: %|30t|%ld") %
                   backwardProbingStopSet_.size();
  backwardProbingStopSet_.insert(
      forwardProbingDiscoverySet_.begin(),
      forwardProbingDiscoverySet_.end());
  LOG(INFO) << boost::format("Discovered Interfaces: %|30t|%1%") %
                   (backwardProbingStopSet_.size());
}

// void Tracerouter::dumpAllTargetsToFile(const std::string& filePath) {
//   LOG(INFO) << "Outputing the targets to file.";
//   std::ofstream dumpFile;
//   dumpFile.open(filePath);
//   struct in_addr paddr;
//   uint32_t it = 0;
//   uint32_t tail = targetList_[it].previousElementOffset;
//   do {
//     if (it != 0 && targetList_[it].peekBackwardTask() != 0) {
//       paddr.s_addr =
//           htonl(dynamic_cast<Ipv4Address*>(targetList_[it].ipAddress.get())
//                     ->getIpv4Address());
//       dumpFile << inet_ntoa(paddr) << "\n";
//     }
//     it = targetList_[it].nextElementOffset;
//   } while (it != tail);
//   dumpFile.close();
//   LOG(INFO) << "All targets are dumped. File path: " << filePath;
// }

void NonstopSet::loadFromFile(absl::string_view filePath) {
  if (filePath.empty()) {
    VLOG(2) << "NonstopSet disabled.";
    return;
  }

  VLOG(2) << "Load NonstopSet from file: " << filePath;
  auto filePathStr = std::string(filePath);
  std::ifstream in(filePathStr);
  int64_t count = 0;
  for (std::string line; std::getline(in, line);) {
    if (!line.empty()) {
      auto result = parseIpFromStringToIpAddress(std::string(line));
      if (result == NULL) continue;
      internalSet_.insert(result);
      count++;
    }
  }
  in.close();
  VLOG(2) << "NonstopSet loads " << count << " addresses from file.";
}

bool NonstopSet::contains(const IpAddress* addr) {
  return (internalSet_.find(const_cast<IpAddress*>(addr)) !=
          internalSet_.end());
}

}  // namespace flashroute

