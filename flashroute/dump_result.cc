/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#include "flashroute/dump_result.h"

#include "glog/logging.h"
#include "absl/numeric/int128.h"

#include "flashroute/address.h"
#include "flashroute/utils.h"

namespace flashroute {

const uint32_t kThreadPoolSize = 2;           // Default thread pool size.
const uint32_t kDumpingTmpBufferSize = 128;   // Char buffer size to dump.
const uint32_t kDumpingIntervalMs = 100;      // Sleep interval.
const uint32_t kDumpingBufferSize = 100000;

ResultDumper::ResultDumper(const std::string& resultFilepath)
    : resultFilepath_(resultFilepath), stopDumping_(false), dumpedCount_(0) {
  resultFilepath_ = resultFilepath;
  threadPool_ = std::make_unique<boost::asio::thread_pool>(kThreadPoolSize);
  dumpingBuffer_ =
      std::make_unique<BoundedBuffer<DataElement>>(kDumpingBufferSize);

  if (resultFilepath_.size() == 0) {
    stopDumping_ = true;
    VLOG(2) << "ResultDumper: ResultDumper disabled.";
  } else {
    VLOG(2) << "ResultDumper: ResultDumper enabled.";
  }
  std::ofstream dumpFile;
  dumpFile.open(resultFilepath_, std::ofstream::binary);
  dumpFile.close();

  // Initialize dumping thread.
  boost::asio::post(*threadPool_.get(), [this]() { runDumpingThread(); });
}

ResultDumper::~ResultDumper() {
  stopDumping_ = true;
  threadPool_->join();
  VLOG(2) << "ResultDumper: ResultDumper recycled. " << dumpedCount_
          << " responses have been dumped.";
}

void ResultDumper::scheduleDumpData(const IpAddress& destination,
                                    const IpAddress& responder,
                                    uint8_t distance, uint32_t rtt,
                                    bool fromDestination, bool ipv4,
                                    void* buffer, size_t size) {
  if (!stopDumping_) {
    absl::uint128 destinationAddr = 0;
    absl::uint128 responderAddr = 0;
    if (destination.isIpv4()) {
      destinationAddr = destination.getIpv4Address();
      responderAddr = responder.getIpv4Address();
    } else {
      destinationAddr = ntohll(destination.getIpv6Address());
      responderAddr = ntohll(responder.getIpv6Address());
    }

    dumpingBuffer_->pushFront({destinationAddr, responderAddr, rtt, distance,
                               static_cast<uint8_t>(fromDestination ? 1 : 0),
                               static_cast<uint8_t>(ipv4 ? 1 : 0)});
  }
}

void ResultDumper::runDumpingThread() {
  VLOG(2) << "ResultDumper: Dumping thread initialized.";
  while (!stopDumping_ || !dumpingBuffer_->empty()) {
    std::ofstream dumpFile;
    dumpFile.open(resultFilepath_, std::ofstream::binary | std::ofstream::app);
    uint8_t buffer[kDumpingTmpBufferSize];
    DataElement tmp;
    int64_t size = dumpingBuffer_->size();
    for (int64_t i = 0; i < size; i++) {
      dumpingBuffer_->popBack(&tmp);
      size_t dumpedSize = binaryDumping(buffer, kDumpingTmpBufferSize, tmp);
      dumpFile.write(reinterpret_cast<char*>(buffer), dumpedSize);
      dumpedCount_++;
    }
    dumpFile.close();
    std::this_thread::sleep_for(std::chrono::milliseconds(kDumpingIntervalMs));
  }
  VLOG(2) << "ResultDumper: Dumping thread recycled.";
}

size_t ResultDumper::binaryDumping(uint8_t* buffer, const size_t maxSize,
                                   const DataElement& dataElement) {
  if (maxSize < 39) return 0;
  *reinterpret_cast<absl::uint128*>(buffer + 0) = dataElement.destination;
  *reinterpret_cast<absl::uint128*>(buffer + 16) = dataElement.responder;

  *reinterpret_cast<uint8_t*>(buffer + 32) = dataElement.rtt;
  *reinterpret_cast<uint8_t*>(buffer + 36) = dataElement.distance;
  *reinterpret_cast<uint8_t*>(buffer + 37) = dataElement.fromDestination;
  *reinterpret_cast<uint8_t*>(buffer + 38) = dataElement.ipv4;
  return 39;
}

}  // namespace flashroute
