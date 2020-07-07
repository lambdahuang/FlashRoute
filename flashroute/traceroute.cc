/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#include "flashroute/traceroute.h"

#include <algorithm>
#include <cstdlib>
#include <limits>
#include <string>
#include <thread>
#include <unordered_set>
#include <iostream>
#include <fstream>
#include <utility>

#include "absl/strings/numbers.h"
#include "absl/strings/string_view.h"
#include "absl/strings/str_split.h"
#include <boost/asio.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/format.hpp>
#include "glog/logging.h"

#include "flashroute/utils.h"
#include "flashroute/network.h"
#include "flashroute/prober.h"
#include "flashroute/udp_prober.h"

namespace flashroute {

// the bit-length of the mask of ip address block, for example, for
// /24 ip address block, the corresponding value is 24
const uint8_t kProbingGranularity = 24;

const uint32_t kDiscoverySetCapacity = 100000;

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
    absl::string_view targetNetwork, const uint8_t defaultSplitTTL,
    const uint8_t defaultPreprobingTTL, const bool forwardProbing,
    const uint8_t forwardProbingGapLimit, const bool redundancyRemoval,
    const bool preprobing, const bool preprobingPrediction,
    const int32_t predictionProximitySpan, const int32_t scanCount,
    const uint32_t seed, const std::string& interface, const uint16_t srcPort,
    const uint16_t dstPort, const std::string& defaultPayloadMessage,
    const int64_t probingRate, const std::string& resultFilepath,
    const bool encodeTimestamp)
    : stopProbing_(false),
      probePhase_(ProbePhase::NONE),
      defaultSplitTTL_(defaultSplitTTL),
      defaultPreprobingTTL_(defaultPreprobingTTL),
      forwardProbingMark_(forwardProbing),
      forwardProbingGapLimit_(forwardProbingGapLimit),
      redundancyRemovalMark_(redundancyRemoval),
      preprobingMark_(preprobing),
      preprobingPredictionMark_(preprobingPrediction),
      preprobingPredictionProximitySpan_(predictionProximitySpan),
      scanCount_(scanCount),
      sentPreprobes_(0),
      preprobeUpdatedCount_(0),
      sentProbes_(0),
      receivedResponses_(0),
      stopMonitoringMark_(false),
      probingIterationRounds_(0),
      seed_(seed),
      interface_(interface),
      srcPort_(srcPort),
      dstPort_(dstPort),
      defaultPayloadMessage_(defaultPayloadMessage),
      probingRate_(probingRate),
      encodeTimestamp_(encodeTimestamp) {
  // Thread pool for handling different purposes.
  threadPool_ = std::make_unique<boost::asio::thread_pool>(kThreadPoolSize);

  // Result dumper.
  resultDumper_ = std::make_unique<ResultDumper>(resultFilepath);

  initializeDcbVector(targetNetwork);

  // initialize the data structure to remember visited interfaces;
  backwardProbingStopSet_.reserve(kDiscoverySetCapacity);
  forwardProbingDiscoverySet_.reserve(kDiscoverySetCapacity);
}

Tracerouter::~Tracerouter() {
  resultDumper_.release();
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
      if (networkManager_.get() != nullptr) {
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
            static_cast<double>(blockRemainingCount_) / targetList_.size() *
            100;
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

void Tracerouter::startScan(bool regenerateDestinationAfterPreprobing) {
  stopProbing_ = false;
  checksumMismatches_ = 0;
  distanceAbnormalities_ = 0;
  auto startTimestamp = std::chrono::steady_clock::now();
  startMetricMonitoring();
  if (preprobingMark_) {
    startPreprobing();
    if (regenerateDestinationAfterPreprobing) {
      generateRandomAddressForEachDcb();
    } else {
      if (defaultSplitTTL_ == defaultPreprobingTTL_) {
        // Folding the preprobing into main probing
        defaultSplitTTL_ -= 1;
        LOG(INFO) << "Main probing starts at TTL 31 since preprobing already "
                     "explores TTL 32.";
      }
    }
  }
  if (!stopProbing_) startProbing();
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

void Tracerouter::goOverAllElement() {
  uint32_t count = 0;
  uint32_t it = 0;
  uint32_t tail = targetList_[it].previousElementOffset;

  do {
    count += 1;
    it = targetList_[it].nextElementOffset;
  } while (it != tail);
  LOG(INFO) << "There are " << count << " elements.";
}

int64_t Tracerouter::getDcbByIpAddress(uint32_t ipAddress,
                                       bool accurateLookup) {
  if (ipAddress >= targetNetworkFirstAddress_ &&
      ipAddress < targetNetworkLastAddress_) {
    int64_t result =
        (ipAddress - targetNetworkFirstAddress_) / blockFactor_ + 1;
    if (accurateLookup) {
      if (targetList_[result].ipAddress == ipAddress) {
        return result;
      } else {
        return -1;
      }
    } else {
      return result;
    }
  } else {
    if (ipAddress < targetNetworkFirstAddress_) {
      return -1;
    } else {
      return targetList_.size() + 1;
    }
  }
}

void Tracerouter::initializeDcbVector(absl::string_view targetNetwork) {
  // target should be a network, e.g. 192.168.1.2/24.
  std::vector<absl::string_view> parts = absl::StrSplit(targetNetwork, "/");
  if (parts.size() != 2) {
    LOG(FATAL) << "Target network format is incorrect!!! " << targetNetwork;
  }
  uint32_t subnetPrefixLength = 0;

  if (!absl::SimpleAtoi(parts[1], &subnetPrefixLength)) {
    LOG(FATAL) << "Failed to parse the target network.";
  }

  uint32_t targetBaseAddress =
      parseIpFromStringToInt(std::string(parts[0]));
  targetNetworkFirstAddress_ =
      getFirstAddressOfBlock(targetBaseAddress, subnetPrefixLength);
  targetNetworkLastAddress_ =
      getLastAddressOfBlock(targetBaseAddress, subnetPrefixLength);
  if (targetNetworkFirstAddress_ >= targetNetworkLastAddress_) {
    LOG(FATAL) << boost::format("Ip address range is incorrect. [%1%, %2%]") %
                      targetNetworkFirstAddress_ %
                      targetNetworkLastAddress_;
  }

  LOG(INFO) << boost::format("The target network is from %1% to %2%.") %
                   parseIpFromIntToString(targetNetworkFirstAddress_) %
                   parseIpFromIntToString(targetNetworkLastAddress_);

  // the range of addresses is inclusive. Therefore, size is right boundary -
  // left Boundary + 1 ip address.
  targetNetworkSize_ = static_cast<int64_t>(targetNetworkLastAddress_) -
                       static_cast<int64_t>(targetNetworkFirstAddress_) + 1;
  blockFactor_ = static_cast<uint32_t>(std::pow(2, 32 - kProbingGranularity));
  uint32_t dcbCount =
      static_cast<uint32_t>(targetNetworkSize_ / blockFactor_) + 1;
  targetList_.reserve(dcbCount);

  // set random seed.
  std::srand(seed_);
  for (int64_t i = 0; i < dcbCount; i++) {
    int64_t nextElement = (dcbCount + i + 1) % dcbCount;
    int64_t previousElement = (dcbCount + i - 1) % dcbCount;
    if (i == 0) {
      // reserved element.
      targetList_.push_back(
          DestinationControlBlock(0, nextElement, previousElement, 8));
    } else {
      // randomly generate IP addresse avoid the first and last ip address
      // in the block.
      targetList_.push_back(DestinationControlBlock(
          targetNetworkFirstAddress_ + ((i - 1) << (32 - kProbingGranularity)) +
              (rand() % (blockFactor_ - 3)) + 2,
          nextElement, previousElement, defaultSplitTTL_));
    }
  }

  blockRemainingCount_ = dcbCount;
  VLOG(2) << boost::format("Created %1% entries (1 reserved dcb).") %
                   dcbCount;
}

void Tracerouter::shuffleDcbSequence(uint32_t seed) {
  std::srand(seed);
  if (targetList_.size() > RAND_MAX) {
    LOG(FATAL) << "Randomization failed: the sequence range is larger than "
                  "the range of randomization function";
  }
  for (uint32_t i = 0; i < targetList_.size(); i++) {
    uint32_t swapTarget = rand() % targetList_.size();
    swapDcbElementSequence(i, swapTarget);
  }
  VLOG(2) << "Traceroute Module: Randomized the probing sequence.";
}

void Tracerouter::swapDcbElementSequence(uint32_t x, uint32_t y) {
  uint32_t nextX = targetList_[x].nextElementOffset;
  uint32_t previousX = targetList_[x].previousElementOffset;
  uint32_t nextY = targetList_[y].nextElementOffset;
  uint32_t previousY = targetList_[y].previousElementOffset;
  if (x == y || nextX == y || nextY == x || previousX == y || previousY == x) {
    return;
  }

  // Not swap element with removed element.
  if (targetList_[x].removed == true || targetList_[y].removed == true) {
    return;
  }

  targetList_[x].nextElementOffset = nextY;
  targetList_[x].previousElementOffset = previousY;
  targetList_[y].nextElementOffset = nextX;
  targetList_[y].previousElementOffset = previousX;

  targetList_[nextY].previousElementOffset = x;
  targetList_[nextX].previousElementOffset = y;

  targetList_[previousY].nextElementOffset = x;
  targetList_[previousX].nextElementOffset = y;
}

int64_t Tracerouter::removeDcbElement(uint32_t x) {
  if (x < 0 || x >= targetList_.size()) {
    return -2;
  }
  if (targetList_[x].removed) {
    return -3;
  }
  uint32_t nextX = targetList_[x].nextElementOffset;
  uint32_t previousX = targetList_[x].previousElementOffset;

  targetList_[nextX].previousElementOffset = previousX;
  targetList_[previousX].nextElementOffset = nextX;
  blockRemainingCount_ -= 1;
  targetList_[x].removed = true;

  if (nextX == x) {
    return -1;
  } else {
    return nextX;
  }
}

void Tracerouter::startPreprobing() {
  // Update status.
  probePhase_ = ProbePhase::PREPROBE;
  // Set up callback function.
  PacketReceiverCallback callback =
      [this](uint32_t destination, uint32_t responder, uint8_t distance,
             bool fromDestination, uint32_t rtt, uint8_t probePhase,
             uint16_t replyIpid, uint8_t replyTtl, uint16_t replySize,
             uint16_t probeSize, uint16_t probeIpid, uint16_t probeSourcePort,
             uint16_t probeDestinationPort) {
        parseIcmpPreprobing(destination, responder, distance, fromDestination);
        resultDumper_->scheduleDumpData(
            destination, responder, distance, fromDestination, rtt, probePhase,
            replyIpid, replyTtl, replySize, probeSize, probeIpid,
            probeSourcePort, probeDestinationPort);
      };

  prober_ =
      std::make_unique<UdpProber>(&callback, 0, kPreProbePhase, dstPort_,
                                  defaultPayloadMessage_, encodeTimestamp_);
  // Set network manager
  networkManager_ =
      std::make_unique<NetworkManager>(prober_.get(), interface_, probingRate_);
  NetworkManager& networkManager = *(networkManager_.get());
  networkManager.startListening();

  auto startTimestamp = std::chrono::steady_clock::now();
  uint32_t it = targetList_[0].nextElementOffset;
  LOG(INFO) << "Start preprobing.";
  do {
    networkManager.schedualProbeRemoteHost(htonl(targetList_[it].ipAddress),
                                           defaultPreprobingTTL_);
    it = targetList_[it].nextElementOffset;
  } while (it != 0 && !stopProbing_);
  std::this_thread::sleep_for(
      std::chrono::milliseconds(kHaltTimeAfterPreprobingSequenceMs));

  networkManager.stopListening();

  int64_t timeDifference =
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::steady_clock::now() - startTimestamp)
          .count();
  LOG(INFO) << boost::format("Preprobing finished (Took %d seconds).") %
                   timeDifference;

  // Update status
  probePhase_ = ProbePhase::NONE;
  sentPreprobes_ = networkManager_.get()->getSentPacketCount();
  receivedResponses_ = networkManager_.get()->getReceivedPacketCount();
  checksumMismatches_ = prober_->checksumMismatches;
  distanceAbnormalities_ = prober_->distanceAbnormalities;
}

void Tracerouter::startProbing() {
  // Update status
  probePhase_ = ProbePhase::PROBE;
  // Set up callback function.
  PacketReceiverCallback callback =
      [this](uint32_t destination, uint32_t responder, uint8_t distance,
             bool fromDestination, uint32_t rtt, uint8_t probePhase,
             uint16_t replyIpid, uint8_t replyTtl, uint16_t replySize,
             uint16_t probeSize, uint16_t probeIpid, uint16_t probeSourcePort,
             uint16_t probeDestinationPort) {
        parseIcmpProbing(destination, responder, distance, fromDestination);
        resultDumper_->scheduleDumpData(
            destination, responder, distance, fromDestination, rtt, probePhase,
            replyIpid, replyTtl, replySize, probeSize, probeIpid,
            probeSourcePort, probeDestinationPort);
      };

  prober_ =
      std::make_unique<UdpProber>(&callback, 0, kMainProbePhase, dstPort_,
                                  defaultPayloadMessage_, encodeTimestamp_);
  networkManager_ =
      std::make_unique<NetworkManager>(prober_.get(), interface_, probingRate_);

  NetworkManager& networkManager = *(networkManager_.get());
  networkManager.startListening();
  int64_t it = 0;
  int64_t next = targetList_[it].nextElementOffset;
  auto startTimestamp = std::chrono::steady_clock::now();
  auto lastRoundTimestamp = std::chrono::steady_clock::now();

  uint32_t remainingBlock = blockRemainingCount_;
  // Take a snapshot for DCBs' links.
  if (scanCount_ > 1) {
    takeDcbSequenceSnapshot();
  }

  LOG(INFO) << "Start main probing.";
  for (int scanCount = 0; scanCount < scanCount_ && !stopProbing_;
       scanCount++) {
    if (scanCount > 0) {
      LOG(INFO) << "< ===========";
      LOG(INFO) << scanCount
                << " extra round of main probing. Destination port offset "
                << scanCount;
      recoverDcbSequenceSnapshot();
      probingIterationRounds_ = 0;
      blockRemainingCount_ = remainingBlock;
      it = 0;
      next = targetList_[it].nextElementOffset;
      prober_->setChecksumOffset(scanCount);
    }
    // send probes to all targeting blocks
    do {
      next = targetList_[it].nextElementOffset;

      if (it == 0) {
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

        if (it == next) {
          // probing is finished.
          break;
        } else {
          it = next;
          continue;
        }
      }

      uint8_t nextForwardTask = targetList_[it].pullForwardTask();
      uint8_t nextBackwardTask = targetList_[it].pullBackwardTask();

      bool hasForwardTask = nextForwardTask != 0;
      bool hasBackwardTask = nextBackwardTask != 0;
      // An entry will be removed only if backward and forward probings are
      // all done.
      if (!hasBackwardTask &&
          (!forwardProbingMark_ || scanCount > 0 || !hasForwardTask)) {
        next = removeDcbElement(it);
      } else {
        if (forwardProbingMark_ && hasForwardTask) {
          // forward probing
          networkManager.schedualProbeRemoteHost(
              htonl(targetList_[it].ipAddress), nextForwardTask);
        }
        if (hasBackwardTask) {
          // backward probing
          networkManager.schedualProbeRemoteHost(
              htonl(targetList_[it].ipAddress), nextBackwardTask);
        }
      }
      it = next;
    } while (!stopProbing_);
    LOG(INFO) << "Scan finished.";
  }
  networkManager.stopListening();
  int64_t timeDifference =
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::steady_clock::now() - startTimestamp)
          .count();
  LOG(INFO) << boost::format("Main probing finished (Took %d seconds).") %
                   timeDifference;
  sentProbes_ = networkManager_.get()->getSentPacketCount();
  receivedResponses_ += networkManager_.get()->getReceivedPacketCount();
  checksumMismatches_ += prober_->checksumMismatches;
  distanceAbnormalities_ += prober_->distanceAbnormalities;
  probePhase_ = ProbePhase::NONE;
}

void Tracerouter::parseIcmpPreprobing(uint32_t destination, uint32_t responder,
                                      uint8_t distance, bool fromDestination) {
  if (!fromDestination) return;
  // Convert the target ip address to the corresponding block index.
  int64_t blockIndex = getDcbByIpAddress(destination, true);
  if (blockIndex == -1 ||
      blockIndex == static_cast<int64_t>(targetList_.size()) + 1) {
    return;
  }

  // The preprobe should update the max ttl always shorter than the ttl of
  // preprobes, otherwise, the target host won't receive preprobe.
  if (targetList_[blockIndex].updateSplitTtl(distance, true)) {
    preprobeUpdatedCount_ += 1;
  }
  if (preprobingPredictionMark_) {
    int64_t predictionLowerBound =
        std::max<int64_t>(blockIndex - preprobingPredictionProximitySpan_, 0);
    int64_t predictionUpperBound = std::min<int64_t>(
        blockIndex + preprobingPredictionProximitySpan_, getBlockCount() - 1);
    for (int64_t i = predictionLowerBound; i <= predictionUpperBound; i++) {
      if (i != blockIndex) {
        if (targetList_[i].updateSplitTtl(distance, false)) {
          preprobeUpdatedCount_ += 1;
        }
      }
    }
  }
}

void Tracerouter::parseIcmpProbing(uint32_t destination, uint32_t responder,
                                   uint8_t distance, bool fromDestination) {
  // Convert the target ip address to the corresponding block index.
  int64_t blockIndex = getDcbByIpAddress(destination, true);
  if (blockIndex == -1 ||
      blockIndex == static_cast<int64_t>(targetList_.size()) + 1) {
    return;
  }
  if (!fromDestination) {
    // Time Exceeded
    if (targetList_[blockIndex].initialBackwardProbingTtl < distance) {
      // The response is from forward probing / the distance is error if
      // forward probing is not activated.
      forwardProbingDiscoverySet_.insert(responder);
    } else {
      // The response is from backward probing.
      if (backwardProbingStopSet_.find(responder) !=
          backwardProbingStopSet_.end()) {
        // We stop only for router interfaces discovered in backward
        // probing.
        if (redundancyRemovalMark_) {
          static_cast<uint64_t>(targetList_[blockIndex].stopBackwardProbing());
        }
      } else {
        backwardProbingStopSet_.insert(responder);
      }
    }
    if (distance <= targetList_[blockIndex].getMaxProbedDistance()) {
      // Set forward probing
      int16_t newMax = std::min<int16_t>(
          distance + static_cast<int16_t>(forwardProbingGapLimit_), kMaxTtl);
      if (newMax >= 0 && newMax <= kMaxTtl) {
        targetList_[blockIndex].setForwardHorizon(static_cast<uint8_t>(newMax));
      }
    }
  } else {
    targetList_[blockIndex].stopForwardProbing();
  }
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
  LOG(INFO) << boost::format("Dropped responses: %|30t|%ld") %
                   (checksumMismatches_ + distanceAbnormalities_);
  LOG(INFO) << boost::format("Checksum Mistatches: %|30t|%ld") %
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

void Tracerouter::dumpAllTargetsToFile(const std::string& filePath) {
  LOG(INFO) << "Outputing the targets to file.";
  std::ofstream dumpFile;
  dumpFile.open(filePath);
  struct in_addr paddr;
  uint32_t it = 0;
  uint32_t tail = targetList_[it].previousElementOffset;
  do {
    if (it != 0 && targetList_[it].peekBackwardTask() != 0) {
      paddr.s_addr = htonl(targetList_[it].ipAddress);
      dumpFile << inet_ntoa(paddr) << "\n";
    }
    it = targetList_[it].nextElementOffset;
  } while (it != tail);
  dumpFile.close();
  LOG(INFO) << "All targets are dumped. File path: " << filePath;
}

void Tracerouter::setDcbIpAddress(const uint32_t newIp) {
  int64_t it = getDcbByIpAddress(newIp, false);
  if (it >= 0 && it < static_cast<int64_t>(targetList_.size())) {
    targetList_[it].ipAddress = newIp;
  }
}

void Tracerouter::generateRandomAddressForEachDcb() {
  // set random seed.
  std::srand(seed_);
  for (int64_t i = 0; i < static_cast<int64_t>(targetList_.size()); i++) {
    if (i != 0) {
      targetList_[i].ipAddress = targetNetworkFirstAddress_ +
                                 ((i - 1) << (32 - kProbingGranularity)) +
                                 rand() % 253 + 2;
    }
  }
  VLOG(2) << boost::format("Randomize %1% entries.") % targetList_.size();
}

void Tracerouter::takeDcbSequenceSnapshot() {
  dcbLinkSnapshot_.resize(0);
  dcbLinkSnapshot_.reserve(targetList_.size());
  for (uint32_t i = 0; i < targetList_.size(); i++) {
    dcbLinkSnapshot_.push_back(
        std::make_pair(targetList_[i].nextElementOffset,
                       targetList_[i].previousElementOffset));
  }
  VLOG(2) << "Traceroute Module: DCB links are recorded.";
}

void Tracerouter::recoverDcbSequenceSnapshot() {
  for (uint32_t i = 0; i < targetList_.size(); i++) {
    targetList_[i].nextElementOffset = dcbLinkSnapshot_[i].first;
    targetList_[i].previousElementOffset = dcbLinkSnapshot_[i].second;
    targetList_[i].resetProbingProgress(rand() % 31 + 1);
  }
  VLOG(2) << "Traceroute Module: DCBs are reset for extra scan.";
}

}  // namespace flashroute

