/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#include "flashroute/dcb_manager.h"

#include "glog/logging.h"

namespace flashroute {

// When granularity has been set to 0, it will be updated based on the type of
// the first inserted address.
DcbManager::DcbManager(const uint64_t reservedSpace, const uint32_t granularity,
                       const uint32_t seed)
    : scanRound(0),
      liveDcbCount_(0),
      granularity_(granularity),
      seed_(seed),
      currentDcb_(NULL),
      lastAddedDcb_(NULL),
      firstAddedDcb_(NULL),
      specialDcb_(NULL) {
  map_.reserve(reservedSpace);
  // insert the special dcb.
  specialDcb_ = addDcb(Ipv4Address(0), 0);
  currentDcb_ = specialDcb_;
  // reset live Dcb count to 0
  liveDcbCount_ = 0;
}

bool DcbManager::hasNext() {
  if (currentDcb_->nextElement == currentDcb_)
    return false;
  else
    return true;
}

DestinationControlBlock* DcbManager::next() {
  currentDcb_ = currentDcb_->nextElement;
  // jump special dcb
  if (currentDcb_ == specialDcb_) {
    currentDcb_ = currentDcb_->nextElement;
    scanRound++;
  }
  return currentDcb_;
}

void DcbManager::resetIterator() {
  currentDcb_ = specialDcb_;
}

void DcbManager::shuffleOrder() {
  // TODO(neohuang): add logic to shuffle the order of iteration.
  // we can put everything in an temp array first and shuffle the order from the
  // array.

  if (map_.size() > RAND_MAX) {
    LOG(FATAL) << "Randomization failed: the sequence range is larger than "
                  "the range of randomization function";
  }

  DestinationControlBlock* tmpArray[map_.size()];
  {
    uint64_t i = 0;
    for (auto it = map_.begin(); it != map_.end(); it++) {
      tmpArray[i++] = it->second;
    }
  }

  srand(seed_);
  for (uint64_t i = 0; i < map_.size(); i++) {
    swapDcbElementSequence(*(tmpArray + i), *(tmpArray + rand() % map_.size()));
  }
}

void DcbManager::randomizeAddress() {
  for (uint64_t i = 0; i < map_.size() - 1; i++) {
    DestinationControlBlock* dcb = this->next();
    dcb->ipAddress->randomizeAddress(granularity_);
  }
}

DestinationControlBlock* DcbManager::getDcbByAddress(
    const IpAddress& addr) const {
  auto result = map_.find(&(const_cast<IpAddress&>(addr)));
  if (result != map_.end()) {
    return result->second;
  }
  return NULL;
}

DestinationControlBlock* DcbManager::addDcb(const IpAddress& addr,
                                            const uint8_t initialTtl) {
  // if granularity is not set, update granularity based on the dcb.
  if (map_.size() != 0 && granularity_ == 0) {
    if (addr.isIpv4())
      granularity_ = 32;
    else
      granularity_ = 128;
  }

  if (map_.find(&(const_cast<IpAddress&>(addr))) != map_.end()) {
    return NULL;
  }

  DestinationControlBlock* tmp =
      new DestinationControlBlock(&addr, NULL, NULL, initialTtl);
  map_.insert({addr.clone(), tmp});

  if (lastAddedDcb_ == NULL && firstAddedDcb_ == NULL) {
    lastAddedDcb_ = tmp;
    firstAddedDcb_ = tmp;
  } else {
    tmp->nextElement = firstAddedDcb_;
    tmp->previousElement = lastAddedDcb_;
    lastAddedDcb_->nextElement = tmp;
    firstAddedDcb_->previousElement = tmp;
    lastAddedDcb_ = tmp;
  }

  liveDcbCount_++;
  return tmp;
}

void DcbManager::removeDcbFromIteration(DestinationControlBlock* dcb) {
  DestinationControlBlock* previous = dcb->previousElement;
  DestinationControlBlock* next = dcb->nextElement;
  previous->nextElement = next;
  next->previousElement = previous;
  liveDcbCount_--;
}

void DcbManager::removeDcbFromIteration(const IpAddress& addr) {
  auto result = map_.find(&(const_cast<IpAddress&>(addr)));
  if (result == map_.end()) {
    return;
  }
  DestinationControlBlock* previous = result->second->previousElement;
  DestinationControlBlock* next = result->second->nextElement;
  previous->nextElement = next;
  next->previousElement = previous;
  liveDcbCount_--;
}

// remove DCB permanently. This is for blacklist.
void DcbManager::deleteDcb(const IpAddress& addr) {
  auto result = map_.find(&(const_cast<IpAddress&>(addr)));
  if (result == map_.end()) {
    return;
  }

  IpAddress* tmpKey  = result->first;
  DestinationControlBlock* tmpValue  = result->second;
  map_.erase(result);
  free(tmpKey);
  free(tmpValue);
  liveDcbCount_--;
  return;
}

void DcbManager::snapshot() {
  // TODO(neohuang): implement snapshot.
}

void DcbManager::reset() {

}

uint64_t DcbManager::size() {
  return map_.size() - 1;
}

uint64_t DcbManager::liveDcbSize() {
  return liveDcbCount_;
}

void DcbManager::swapDcbElementSequence(DestinationControlBlock* x,
                                        DestinationControlBlock* y) {
  DestinationControlBlock* nextX = x->nextElement;
  DestinationControlBlock* previousX = x->previousElement;
  DestinationControlBlock* nextY = y->nextElement;
  DestinationControlBlock* previousY = y->previousElement;
  if (x == y || nextX == y || nextY == x || previousX == y || previousY == x) {
    return;
  }

  // Not swap element with removed element.
  if (x->removed == true || y->removed == true) {
    return;
  }

  x->nextElement = nextY;
  x->previousElement = previousY;
  y->nextElement = nextX;
  y->previousElement = previousX;

  nextY->previousElement = x;
  nextX->previousElement = y;

  previousY->nextElement = x;
  previousX->nextElement = y;
}

}  // namespace flashroute

