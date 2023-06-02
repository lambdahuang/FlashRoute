/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#pragma once

#include <chrono>
#include <cmath>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>
#include <utility>

#include "absl/strings/string_view.h"
#include <boost/asio/thread_pool.hpp>
#include "glog/logging.h"

#include "flashroute/address.h"
#include "flashroute/dcb.h"
#include "flashroute/dcb_manager.h"
#include "flashroute/dump_result.h"
#include "flashroute/network.h"
#include "flashroute/prober.h"

namespace flashroute {

enum class ProbePhase { PREPROBE, PROBE, NONE };

enum class ProberType { UDP_PROBER, UDP_IDEMPOTENT_PROBER };

class NonstopSet {
  public:
   void loadFromFile(absl::string_view filePath);
   bool contains(const IpAddress* addr);

  private:
   std::unordered_set<IpAddress*, IpAddressHash, IpAddressEquality>
       internalSet_;
};

/**
 * Traceroute module contains the major logics and strategies of probing.
 * Examples:
 * Tracerouter tracerouter(
 *    dcbManager,                 // an instance of DcbManager
 *    networkManager,             // an instance of NetworkManager
 *    nonstopSet,                 // a set of addresses that backward probing
 *                                // should not stop when hitting.
 *    16,                         // Split TTL
 *    32,                         // Preprobing TTL
 *    true,                       // Forward probing switch.
 *    5,                          // Forward Probing gaplimit.
 *    true,                       // Remove redundancy in backward probing.
 *    true,                       // Perform preprobing to measure distances.
 *    true,                       // Perform distance prediction in preprobing.
 *    5,                          // Set the proximity span to appy prediction.
 *    1,                          // Set the number of scans. The scans after
 *                                // first round of scan will be treated as
 *                                // discovery-optimized mode.
 *    3,                          // Set the seed for guiding random processes,
 *                                // for example, destination generation or
 *                                // probing sequence randomization. 
 *    53,                         // Set the expected source port (can be
 *                                // overrided by algorithm).
 *    53,                         // Set the expected destination port.
 *    "test",                     // Message to encode into the payload of each
 *                                // probe.   
 *    true,                       // Control whether to encode timestamp to each
 *                                // probe. (Test function).
 *    0,                          // ttl offset to shift the range of ttl
 *    true                        // Randomize addresses in following scans.
 * );
 * 
 * // startScan accepts two parameters:
 * // regenerateDestinationAfterPreprobing: control whether or not to
 * // regenerate destinations after preprobing.
 * // withTimestamp: 
 * 
 * tracerouter.startScan(false, true);
 * tracerouter.stopScan();
 * 
 */

class Tracerouter {
 public:
  // Define the constructor for mock testing.
  Tracerouter() {}
  Tracerouter(DcbManager* dcbManager, NetworkManager* networkManager,
              ResultDumper* resultDumper, NonstopSet* nonstopSet,
              const uint8_t defaultSplitTTL, const uint8_t defaultPreprobingTTL,
              const bool forwardProbing, const uint8_t forwardProbingGapLimit,
              const bool redundancyRemoval, const bool preprobing,
              const bool preprobingPrediction,
              const int32_t predictionProximitySpan, const int32_t scanCount,
              const uint16_t srcPort, const uint16_t dstPort,
              const std::string& defaultPayloadMessage,
              const bool encodeTimestamp, const uint8_t ttlOffset,
              const bool randomizeAddressinExtraScans);

  ~Tracerouter();

  void startScan(ProberType proberType, bool ipv4,
                 bool randomizeAddressAfterPreprobing);

  void stopScan() { stopProbing_ = true; }

 private:
  DcbManager* dcbManager_;
  // Control probing to stop
  bool stopProbing_;
  // Record the current probe phase which will be used for logging
  ProbePhase probePhase_;

  ResultDumper* resultDumper_;

  std::unique_ptr<boost::asio::thread_pool> threadPool_;

  std::unique_ptr<Prober> prober_;
  NetworkManager* networkManager_;
  
  NonstopSet* nonstopSet_;

  // The default max ttl which is also the starting hop-distance of probing.
  uint8_t defaultSplitTTL_;

  // The ttl to preprobe targets.
  uint8_t defaultPreprobingTTL_;

  // The offset of ttl.
  uint8_t ttlOffset_;

  // Control whether or not to forward probe. Per our design, we can forward
  // probe the router interfaces at a hop-distance further if tailing N nodes
  // repond TTL-expired message.
  bool forwardProbingMark_;
  // If tailing forwardProbingGapLimit_ nodes on the route respond a
  // TTL-expired message, we do the forward probing.
  uint8_t forwardProbingGapLimit_;

  // For each target, the program probes from the edge, the furthest distance,
  // back to the root so long as the no discovered router is found on the path.
  // Doing so let the tracerouter only works on the undiscovered part of path.
  bool redundancyRemovalMark_;

  bool preprobingMark_;
  bool preprobingPredictionMark_;
  int32_t preprobingPredictionProximitySpan_;

  int32_t scanCount_;
  bool randomizeAddressInExtraScans_;

  // Metrics
  uint64_t sentPreprobes_;
  uint64_t preprobeUpdatedCount_;

  uint64_t sentProbes_;
  uint64_t receivedResponses_;
  bool stopMonitoringMark_;
  uint32_t probingIterationRounds_;

  uint64_t droppedResponses_;
  uint64_t checksumMismatches_;
  uint64_t distanceAbnormalities_;

  // Record all observed interfaces in backward probing.
  std::unordered_set<IpAddress*, IpAddressHash,
                     IpAddressEquality>
      backwardProbingStopSet_;

  // Record all observed interfaces in forward probing.
  std::unordered_set<IpAddress*, IpAddressHash,
                     IpAddressEquality>
      forwardProbingDiscoverySet_;

  // Seed for randomization.
  uint32_t seed_;

  // Network
  // Source port number will be override if packet encoding needs to use source
  // port to store information.

  uint16_t srcPort_;
  uint16_t dstPort_;

  std::string defaultPayloadMessage_;

  // The traversing sequence of Dcbs.
  std::vector<std::pair<uint32_t, uint32_t>> dcbLinkSnapshot_;

  // The variable to encode timestamp.
  bool encodeTimestamp_;

  void startPreprobing(ProberType proberType, bool ipv4);

  void startProbing(ProberType proberType, bool ipv4);

  bool parseIcmpPreprobing(const IpAddress& destination,
                           const IpAddress& responder, uint8_t distance,
                           bool fromDestination);

  bool parseIcmpProbing(const IpAddress& destination,
                        const IpAddress& responder, uint8_t distance,
                        bool fromDestination);

  void startMetricMonitoring();

  void stopMetricMonitoring();

  void calculateStatistic(uint64_t elapsedTime);
};

}  // namespace flashroute
