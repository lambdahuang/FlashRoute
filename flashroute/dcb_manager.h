/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#pragma once

#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "flashroute/address.h"
#include "flashroute/dcb.h"


namespace flashroute {

class DcbManager {
 public:
  int32_t scanRound = 0;

  explicit DcbManager(const uint64_t reservedSpace, const uint32_t granularity,
                      const uint32_t seed, const bool coarseFind);

  ~DcbManager();

  // return true if there is any dcb in iteration list.
  bool hasNext();

  // get next address.
  DestinationControlBlock* next();

  // peek the next address.
  DestinationControlBlock* peek() const;

  // reset iterator position.
  void resetIterator();

  // shuffle the order of iteration.
  void shuffleOrder();

  // randomize addresses.
  void randomizeAddress();

  // get DCB based on the address.
  DestinationControlBlock* getDcbByAddress(const IpAddress& pseudo) const;

  // get all DCBs fall in prefix.
  std::vector<DestinationControlBlock*>* getDcbsByAddress(
      const IpAddress& pseudo) const;

  // insert address.
  DestinationControlBlock* addDcb(const IpAddress& addr,
                                  const uint8_t initialTtl,
                                  uint16_t sourcePort);

  void removeDcbFromIteration(DestinationControlBlock* dcb);

  // remove DCB from future iteration.
  void removeDcbFromIteration(const IpAddress& addr);

  // remove DCB permanently. This is for blacklist.
  void deleteDcb(const IpAddress& addr);

  // snapshot the current status.
  void snapshot();

  // recover to the snapshot.
  void reset();

  // Shuffle address using the method.
  void shuffleAddress();

  // return the number of the DCBs that are in iteration.
  uint64_t liveDcbSize();

  // return the number of the DCBs.
  uint64_t size();

  // release the resource allocated for coase address look up.
  void releaseCoarseMapping();

 private:
  uint64_t liveDcbCount_ = 0;
  uint32_t granularity_;
  uint32_t seed_;

  std::unique_ptr<std::unordered_map<IpAddress*, DestinationControlBlock*,
                                     IpAddressHash, IpAddressEquality>>
      map_;

  std::unique_ptr<
      std::unordered_map<IpNetwork*, std::vector<DestinationControlBlock*>,
                         IpNetworkHash, IpNetworkEquality>>
      coarseMap_;

  DestinationControlBlock* currentDcb_;
  DestinationControlBlock* lastAddedDcb_;
  DestinationControlBlock* firstAddedDcb_;

  // specialDcb helps identify the beginning of iteration.
  DestinationControlBlock* specialDcb_;

  void swapDcbElementSequence(DestinationControlBlock* x,
                              DestinationControlBlock* y);

  void addToCoarseMap(DestinationControlBlock* dcb);

  void releaseAccurateMapping();
};

}  // namespace flashroute
