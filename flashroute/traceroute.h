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

#include "flashroute/dcb.h"
#include "flashroute/network.h"
#include "flashroute/udp_prober.h"
#include "flashroute/dump_result.h"

namespace flashroute {

enum class ProbePhase { PREPROBE, PROBE, NONE };

/**
 * Traceroute module contains the major logics and strategies of probing.
 * Examples:
 * Tracerouter tracerouter(
 *    "123.123.123.123/24",       // Target network
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
 *    "eth0",                     // Specify the interface for scan.
 *    53,                         // Set the expected source port (can be
 *                                // overrided by algorithm).
 *    53,                         // Set the expected destination port.
 *    "test",                     // Message to encode into the payload of each
 *                                // probe.   
 *    10000,                      // Set probing rate. 
 *    "./output.dat",             // Set the output filepath.
 *    true                        // Control whether to encode timestamp to each
 *                                // probe. (Test function)
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
  Tracerouter(const absl::string_view targetNetwork,
              const uint8_t defaultSplitTTL, const uint8_t defaultPreprobingTTL,
              const bool forwardProbing, const uint8_t forwardProbingGapLimit,
              const bool redundancyRemoval, const bool preprobing,
              const bool preprobingPrediction,
              const int32_t predictionProximitySpan, const int32_t scanCount,
              const uint32_t seed, const std::string& interface,
              const uint16_t srcPort, const uint16_t dstPort,
              const std::string& defaultPayloadMessage,
              const int64_t probingRate, const std::string& resultFilepath,
              const bool encodeTimestamp);

  ~Tracerouter();

  void startScan(bool regenerateDestinationAfterPreprobing);

  void stopScan() { stopProbing_ = true; }

  void startMetricMonitoring();

  void stopMetricMonitoring();

  // Randomizing the probing sequence helps avoid overprobing some router
  // interfaces in a short period of time, which may trigger the ICMP-rate
  // limit.
  void shuffleDcbSequence(uint32_t seed);

  // Remove the element and return the offset pointing to the next element. if
  // the removed element is the last element, function will return -1, if the
  // remove element does not exist, return -2, if the removed element is removed
  // already, return -3.
  //
  virtual int64_t removeDcbElement(uint32_t x);

  // Iterate through all targets in probing sequence and print the number of
  // targets to LOG.
  void goOverAllElement();

  virtual int64_t getDcbByIpAddress(uint32_t ipAddress, bool accurateLookup);

  // Get the number of DCBs.
  int64_t getBlockCount() { return targetList_.size(); }

  void calculateStatistic(uint64_t elapsedTime);

  // Load a list of targets that are likely responsive to preprobing.
  void loadTargetsFromFile(absl::string_view filePath);

  // Experiment feature. Dump all targets to a file.
  void dumpAllTargetsToFile(const std::string& filePath);

  // Set IP address for DCB.
  void setDcbIpAddress(const uint32_t newIp);

  // Randomize the destinations IP addresses.
  void generateRandomAddressForEachDcb();

 private:
  // Control probing to stop
  bool stopProbing_;
  // Record the current probe phase which will be used for logging
  ProbePhase probePhase_;

  std::unique_ptr<ResultDumper> resultDumper_;

  std::unique_ptr<boost::asio::thread_pool> threadPool_;

  std::unique_ptr<UdpProber> prober_;
  std::unique_ptr<NetworkManager> networkManager_;

  // The default max ttl which is also the starting hop-distance of probing.
  uint8_t defaultSplitTTL_;

  // The ttl to preprobe targets.
  uint8_t defaultPreprobingTTL_;

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

  // The targets is not always from 0 to 2^32-1, which is the preset for the
  // whole Ipv4 address space scanning. We accept targets is a range of Ip
  // addresses, which starts and ends at given points.
  // targetNetworkFirstAddress_ is the beginning of the range of ip addresses.
  uint32_t targetNetworkFirstAddress_;
  uint32_t targetNetworkLastAddress_;
  // targetNetworkSize_ is the number of unicast ip addresses in the range.
  int64_t targetNetworkSize_;
  // Since we split the probing range into ip blocks, where each block
  // contains the same number blockFactor_ of uni-cast ip addresses.
  // For example, if we proble /24 prefixed ip addresses, the blockFactor_ is
  // 2^8 = 256, which means each block contains 256 ip addresses.
  int64_t blockFactor_;
  // blockInitialCount_ is the number of blocks created in initialization.
  // Since we need to remove the blacklist ip addresses later, we use
  // blockInitialCount_ to represent the number of blocks created in the
  // memory, different from blockRemainingCount_, which represents the number
  // of the blocks remained unfinished.
  uint32_t blockRemainingCount_;
  std::vector<DestinationControlBlock> targetList_;

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
  std::unordered_set<uint32_t> backwardProbingStopSet_;

  // Record all observed interfaces in forward probing.
  std::unordered_set<uint32_t> forwardProbingDiscoverySet_;

  // Seed for randomization.
  uint32_t seed_;

  // Network
  // Source port number will be override if packet encoding needs to use source
  // port to store information.
  std::string interface_;

  uint16_t srcPort_;
  uint16_t dstPort_;

  std::string defaultPayloadMessage_;

  int64_t probingRate_;

  // The traversing sequence of Dcbs.
  std::vector<std::pair<uint32_t, uint32_t>> dcbLinkSnapshot_;

  // The variable to encode timestamp.
  bool encodeTimestamp_;

  void initializeDcbVector(absl::string_view targetNetwork);

  void swapDcbElementSequence(uint32_t x, uint32_t y);

  void startPreprobing();

  void startProbing();

  void parseIcmpPreprobing(uint32_t destination, uint32_t responder,
                           uint8_t distance, bool fromDestination);

  void parseIcmpProbing(uint32_t destination, uint32_t responder,
                        uint8_t distance, bool fromDestination);

  void takeDcbSequenceSnapshot();

  void recoverDcbSequenceSnapshot();
};

}  // namespace flashroute
