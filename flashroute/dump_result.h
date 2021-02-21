/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#pragma once

#include <memory>
#include <string>

#include <boost/asio.hpp>
#include <boost/process.hpp>
#include "absl/strings/string_view.h"
#include "absl/numeric/int128.h"

#include "flashroute/address.h"
#include "flashroute/bounded_buffer.h"

namespace flashroute {

struct DataElement {
  absl::uint128 destination;
  absl::uint128 responder;
  uint32_t rtt;
  uint8_t distance;
  uint8_t fromDestination;
  uint8_t ipv4;
};


class ResultDumper {
 public:
  explicit ResultDumper(const std::string& resultFilepath);
  ~ResultDumper();

  void scheduleDumpData(const IpAddress& destination,
                        const IpAddress& responder, uint8_t distance,
                        uint32_t rtt, bool fromDestination, bool ipv4,
                        void* buffer, size_t size);

 private:
  // File path to dump the result.
  std::string resultFilepath_;

  // Thread pool
  std::unique_ptr<boost::asio::thread_pool> threadPool_;

  std::unique_ptr<BoundedBuffer<DataElement>> dumpingBuffer_;

  bool stopDumping_;

  uint64_t dumpedCount_;

  // Dumping thread.
  void runDumpingThread();


  // Dumping logic
  size_t binaryDumping(uint8_t* buffer, const size_t maxSize,
                       const DataElement& dataElement);
};

}  // namespace flashroute
