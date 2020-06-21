/* Copyright (C) 2019 Neo Huang - All Rights Reserved */

#include "flashroute/dump_result.h"
#include "glog/logging.h"

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

void ResultDumper::scheduleDumpData(uint32_t destination, uint32_t responder,
                                    uint8_t distance, bool fromDestination,
                                    uint32_t rtt, uint8_t probePhase,
                                    uint16_t replyIpid, uint8_t replyTtl,
                                    uint16_t replySize, uint16_t probeSize,
                                    uint16_t probeIpid,
                                    uint16_t probeSourcePort,
                                    uint16_t probeDestinationPort) {
  if (!stopDumping_) {
    dumpingBuffer_->pushFront(
        {destination, responder, distance, (fromDestination ? 1 : 0), rtt,
         probePhase, replyIpid, replyTtl, replySize, probeSize, probeIpid,
         probeSourcePort, probeDestinationPort});
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
  if (maxSize < 28) return 0;
  *reinterpret_cast<uint32_t*>(buffer + 0) = dataElement.destination;
  *reinterpret_cast<uint32_t*>(buffer + 4) = dataElement.responder;

  *reinterpret_cast<uint8_t*>(buffer + 8) = dataElement.distance;
  *reinterpret_cast<uint8_t*>(buffer + 9) = dataElement.fromDestination;
  *reinterpret_cast<uint32_t*>(buffer + 10) = dataElement.rtt;
  *reinterpret_cast<uint8_t*>(buffer + 14) = dataElement.probePhase;

  *reinterpret_cast<uint16_t*>(buffer + 15) = dataElement.replyIpid;
  *reinterpret_cast<uint8_t*>(buffer + 17) = dataElement.replyTtl;
  *reinterpret_cast<uint16_t*>(buffer + 18) = dataElement.replySize;
  *reinterpret_cast<uint16_t*>(buffer + 20) = dataElement.probeSize;
  *reinterpret_cast<uint16_t*>(buffer + 22) = dataElement.probeIpid;
  *reinterpret_cast<uint16_t*>(buffer + 24) = dataElement.probeSourcePort;
  *reinterpret_cast<uint16_t*>(buffer + 26) = dataElement.probeDestinationPort;
  return 28;
}

}  // namespace flashroute
