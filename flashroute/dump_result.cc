/* Copyright (C) 2019 Neo Huang - All Rights Reserved */

#include "glog/logging.h"
#include "absl/numeric/int128.h"

#include "flashroute/address.h"
#include "flashroute/dump_result.h"

namespace flashroute {

const uint32_t kThreadPoolSize = 2;           // Default thread pool size.
const uint32_t kDumpingTmpBufferSize = 128;   // Char buffer size to dump.
const uint32_t kDumpingIntervalMs = 100;      // Sleep interval.
const uint32_t kDumpingBufferSize = 100000;

ResultDumper::ResultDumper(const std::string& resultFilepath)
    : resultFilepath_(resultFilepath), stopDumping_(false) {
  resultFilepath_ = resultFilepath;
  threadPool_ = std::make_unique<boost::asio::thread_pool>(kThreadPoolSize);
  dumpingBuffer_ =
      std::make_unique<BoundedBuffer<DataElement>>(kDumpingBufferSize);

  if (resultFilepath_.size() == 0) {
    stopDumping_ = true;
    VLOG(2) << "ResultDumper: ResultDumper disabled.";
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
  VLOG(2) << "ResultDumper: ResultDumper recycled.";
}

void ResultDumper::scheduleDumpData(
    const IpAddress& destination, const IpAddress& responder, uint8_t distance,
    bool fromDestination, uint32_t rtt, uint8_t probePhase, uint16_t replyIpid,
    uint8_t replyTtl, uint16_t replySize, uint16_t probeSize,
    uint16_t probeIpid, uint16_t probeSourcePort,
    uint16_t probeDestinationPort) {
  if (!stopDumping_) {
    absl::uint128 destinationAddr = 0;
    absl::uint128 responderAddr = 0;
    if (destination.isIpv4()) {
      destinationAddr = destination.getIpv4Address();
      responderAddr = responder.getIpv4Address();
    } else {
      destinationAddr = destination.getIpv6Address();
      responderAddr = responder.getIpv4Address();
    }

    dumpingBuffer_->pushFront({destinationAddr, responderAddr, distance,
                               static_cast<uint8_t>(fromDestination ? 1 : 0),
                               rtt, probePhase, replyIpid, replyTtl, replySize,
                               probeSize, probeIpid, probeSourcePort,
                               probeDestinationPort});
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
    }
    dumpFile.close();
    std::this_thread::sleep_for(std::chrono::milliseconds(kDumpingIntervalMs));
  }
  VLOG(2) << "ResultDumper: Dumping thread recycled.";
}

size_t ResultDumper::binaryDumping(uint8_t* buffer, const size_t maxSize,
                                   const DataElement& dataElement) {
  if (maxSize < 52) return 0;
  *reinterpret_cast<absl::uint128*>(buffer + 0) = dataElement.destination;
  *reinterpret_cast<absl::uint128*>(buffer + 16) = dataElement.responder;

  *reinterpret_cast<uint8_t*>(buffer + 32) = dataElement.distance;
  *reinterpret_cast<uint8_t*>(buffer + 33) = dataElement.fromDestination;
  *reinterpret_cast<uint32_t*>(buffer + 34) = dataElement.rtt;
  *reinterpret_cast<uint8_t*>(buffer + 38) = dataElement.probePhase;

  *reinterpret_cast<uint16_t*>(buffer + 39) = dataElement.replyIpid;
  *reinterpret_cast<uint8_t*>(buffer + 41) = dataElement.replyTtl;
  *reinterpret_cast<uint16_t*>(buffer + 42) = dataElement.replySize;
  *reinterpret_cast<uint16_t*>(buffer + 44) = dataElement.probeSize;
  *reinterpret_cast<uint16_t*>(buffer + 46) = dataElement.probeIpid;
  *reinterpret_cast<uint16_t*>(buffer + 48) = dataElement.probeSourcePort;
  *reinterpret_cast<uint16_t*>(buffer + 50) = dataElement.probeDestinationPort;
  return 52;
}

}  // namespace flashroute
