#include <iostream>
#include <fstream>
#include <cstring> // for std::strlen
#include <cstddef> // for std::size_t -> is a typedef on an unsinged int
#include <unordered_set>

#include "glog/logging.h"
#include "absl/flags/usage.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/str_cat.h"
#include "absl/numeric/int128.h"

#include "flashroute/dump_result.h"
#include "flashroute/address.h"

using flashroute::IpAddress;
using flashroute::Ipv4Address;
using flashroute::IpAddressHash;
using flashroute::IpAddressEquality;

ABSL_FLAG(std::string, target_file, "", "Dump targets to file.");

struct DataElement {
  uint32_t destination[4];
  uint32_t responder[4];
  uint32_t rtt;
  uint8_t distance;
  uint8_t fromDestination;
  uint8_t ipv4;
} __attribute__((packed));;

int main(int argc, char* argv[]) {
  FLAGS_alsologtostderr = 1;
  google::InitGoogleLogging(argv[0]);
  absl::SetProgramUsageMessage("This program does nothing.");
  absl::ParseCommandLine(argc, argv);

  LOG(INFO) << "Start to read data from: " << absl::GetFlag(FLAGS_target_file);
  flashroute::ResultDumper resultDumper{
      absl::StrCat(absl::GetFlag(FLAGS_target_file), "_unique_interface")};

  std::unordered_set<IpAddress *, IpAddressHash, IpAddressEquality> observedInterface;

  std::ifstream inFile;
  inFile.open(absl::GetFlag(FLAGS_target_file),
              std::ios::in | std::ios::binary);
  DataElement buffer;
  uint64_t records = 0;
  uint64_t interface = 0;
  uint64_t dumped = 0;
  while (inFile.peek() != EOF) {
    inFile.read(reinterpret_cast<char *>(&buffer), 39);
    records++;
    if (buffer.ipv4 == 1) {
        // IPv4 address handling.
        auto addr = new Ipv4Address(buffer.responder[0]);
        if (buffer.fromDestination == true) {
          dumped++;
          resultDumper.scheduleDumpData(
              *addr, Ipv4Address{buffer.destination[0]}, buffer.distance, buffer.rtt,
              static_cast<bool>(buffer.fromDestination), true, nullptr, 0);
        } else if (observedInterface.find(addr) == observedInterface.end()) {
          observedInterface.insert(addr);
          dumped++;
          resultDumper.scheduleDumpData(
              *addr, Ipv4Address{buffer.destination[0]}, buffer.distance, buffer.rtt,
              static_cast<bool>(buffer.fromDestination), true, nullptr, 0);
          if (buffer.fromDestination == 0)
            interface += 1;

        } else {
          delete addr;
        }
    } else {
        // IPv6 address handling
        // TODO: we need to add the code logic handle IPv6 Address.
    }
  }

  inFile.close();
  LOG(INFO) << "Processed " << records << " records.";
  LOG(INFO) << "Dumped " << dumped << " records.";
  LOG(INFO) << "There are " << interface << " unique interfaces.";

}