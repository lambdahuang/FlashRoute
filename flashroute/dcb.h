/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#pragma once

#include <memory>
#include <mutex>

#include "flashroute/address.h"

namespace flashroute {

class DestinationControlBlock {
 public:
  std::unique_ptr<IpAddress> ipAddress;
  DestinationControlBlock* nextElement;
  DestinationControlBlock* previousElement;
  bool removed;
  // the initial TTL when we start backward probing. This value will be used to
  // prevent the traceroute to put router interfaces discovered in
  // forward-probing into the stop set.
  uint8_t initialBackwardProbingTtl;

  DestinationControlBlock(const IpAddress* ip,
                          DestinationControlBlock* _nextElement,
                          DestinationControlBlock* _previousElement,
                          const uint8_t initialTtl);

  /**
   * set the split-TTL, if the given TTL is confirmed, the second variabble
   * should be true, otherwise, false; this is to distinguish accurate TTL vs
   * predicted TTL.
   */
  bool updateSplitTtl(uint8_t ttlToUpdate, bool confirmResult);

  /**
   * stop backward probing by setting the nextBackwardHop to 0, and remains the
   * current backward ttl.
   */
  uint8_t stopBackwardProbing();

  /**
   * return current backward ttl and move backward.
   */
  uint8_t pullBackwardTask();

  /**
   * return true if there is backward probing task.
   */
  bool hasBackwardTask();

  /**
   * return current backward ttl.
   */
  uint8_t peekBackwardTask();

  /**
   * return true if there is forward probing task.
   */
  bool hasForwardTask();

  /**
   * return current forward ttl and move forward, 0 if there is no forward task.
   */
  uint8_t pullForwardTask();

  /**
   * return current forward ttl and move forward, 0 if there is no forward task.
   */
  void stopForwardProbing();

  /**
   * return the maximum TTL that is probed already.
   */
  int16_t getMaxProbedDistance();

  /**
   * set forward probing horizon.
   */
  void setForwardHorizon(uint8_t forwardExploredHop);

  /**
   * reset the probing progress. Will be deployed in discovery-optimized mode.
   */
  void resetProbingProgress(uint8_t ttl);

  bool isPreprobed() const;

  uint8_t peekForwardHop() const;

 private:
  uint8_t nextBackwardHop_;
  // std::unique_ptr<std::mutex> ttlToProbeMutex_;

  bool preprobedMark_;
  // if true, the current initial TTL is from the accurate distance measurement
  // result, otherwise, false.
  bool accurateDistanceMark_;
  // std::unique_ptr<std::mutex> preprobedMarkMutex_;

  // The maximal hop-distance that is probed already.
  uint8_t nextForwardHop_;
  // std::unique_ptr<std::mutex> maxProbedHopMutex_;

  // The maximal hop-distance that is expected to be explored by forward
  // probbing. We probe router
  uint8_t forwardHorizon_;
  // std::unique_ptr<std::mutex> forwardExploredHopMutex_;
  std::unique_ptr<std::atomic_flag> testAndSet;
};

}  // namespace flashroute
