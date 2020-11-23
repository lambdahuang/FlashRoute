#include <memory>
#include <mutex>

#include "flashroute/dcb.h"

namespace flashroute {

DestinationControlBlock::DestinationControlBlock(uint32_t ip,
                                                 uint32_t nextElement,
                                                 uint32_t previousElement,
                                                 uint8_t initialTtl)
    : ipAddress(ip),
      nextElementOffset(nextElement),
      previousElementOffset(previousElement),
      removed(false),
      initialBackwardProbingTtl(initialTtl),
      nextBackwardHop_(initialTtl),
      preprobedMark_(false),
      accurateDistanceMark_(false),
      nextForwardHop_(initialTtl + 1),
      forwardHorizon_(initialTtl) {
  testAndSet = std::make_unique<std::atomic_flag>();
  (*testAndSet).clear();
}

bool DestinationControlBlock::updateSplitTtl(uint8_t ttlToUpdate,
                                               bool confirmResult) {
  while (testAndSet->test_and_set(std::memory_order_acquire)) {}
  bool result = !preprobedMark_;
  // If the target does not have any confirmed hop-distance, we are allowed to
  // update it.
  if (!accurateDistanceMark_) {
    {
      nextBackwardHop_ = ttlToUpdate;
      // update the initial TTL for backward probing.
      initialBackwardProbingTtl = ttlToUpdate;
      // Also update the next forward hop.
      nextForwardHop_ = ttlToUpdate + 1;
      forwardHorizon_ = ttlToUpdate;
      // If the updated TTL is from an accurate preprobing result, we lock the
      // future update.
      if (confirmResult) {
        accurateDistanceMark_ = true;
      }
      preprobedMark_ = true;
    }
  }
  testAndSet->clear(std::memory_order_release);
  return result;
}

uint8_t DestinationControlBlock::stopBackwardProbing() {
  while (testAndSet->test_and_set(std::memory_order_acquire)) {}
  uint8_t remains = nextBackwardHop_;
  nextBackwardHop_ = 0;
  testAndSet->clear(std::memory_order_release);
  return remains;
}

uint8_t DestinationControlBlock::pullBackwardTask() {
  while (testAndSet->test_and_set(std::memory_order_acquire)) {}
  if (nextBackwardHop_ > 0) {
    auto tmp = nextBackwardHop_--;
    testAndSet->clear(std::memory_order_release);
    return tmp;
  } else {
    testAndSet->clear(std::memory_order_release);
    return 0;
  }
}

bool DestinationControlBlock::hasBackwardTask() {
  while (testAndSet->test_and_set(std::memory_order_acquire)) {
  }
  auto tmp = nextBackwardHop_ > 0;
  testAndSet->clear(std::memory_order_release);
  return tmp;
}

uint8_t DestinationControlBlock::peekBackwardTask() {
  while (testAndSet->test_and_set(std::memory_order_acquire)) {
  }
  auto tmp = nextBackwardHop_;
  testAndSet->clear(std::memory_order_release);
  return tmp;
}

bool DestinationControlBlock::hasForwardTask() {
  while (testAndSet->test_and_set(std::memory_order_acquire)) {
  }
  auto tmp = forwardHorizon_ >= nextForwardHop_;
  testAndSet->clear(std::memory_order_release);
  return tmp;
}

uint8_t DestinationControlBlock::pullForwardTask() {
  while (testAndSet->test_and_set(std::memory_order_acquire)) {
  }
  if (forwardHorizon_ >= nextForwardHop_) {
    auto tmp = nextForwardHop_++;
    testAndSet->clear(std::memory_order_release);
    return tmp;
  } else {
    testAndSet->clear(std::memory_order_release);
    return 0;
  }
}

void DestinationControlBlock::stopForwardProbing() {
  while (testAndSet->test_and_set(std::memory_order_acquire)) {
  }
  forwardHorizon_ = 0;
  testAndSet->clear(std::memory_order_release);
}

int16_t DestinationControlBlock::getMaxProbedDistance() {
  while (testAndSet->test_and_set(std::memory_order_acquire)) {
  }
  auto tmp = nextForwardHop_ - 1;
  testAndSet->clear(std::memory_order_release);
  return tmp;
}

void DestinationControlBlock::setForwardHorizon(uint8_t forwardExploredHop) {
  while (testAndSet->test_and_set(std::memory_order_acquire)) {
  }
  // forwardHorizon_ == 0 means that the forward probing is done;
  // therefore, we will not update the variable regarding the forward probing.
  if (forwardHorizon_ == 0) {
    testAndSet->clear(std::memory_order_release);
    return;
  }
  if (forwardExploredHop > forwardHorizon_) {
    forwardHorizon_ = forwardExploredHop;
  }
  testAndSet->clear(std::memory_order_release);
}

void DestinationControlBlock::resetProbingProgress(uint8_t ttl) {
  nextBackwardHop_ = ttl;
  initialBackwardProbingTtl = ttl;
  nextForwardHop_ = ttl + 1;
  forwardHorizon_ = ttl;
  removed = false;
}

}  // namespace flashroute


