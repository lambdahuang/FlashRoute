#include <cstddef> // for std::size_t -> is a typedef on an unsinged int
#include <cstring> // for std::strlen
#include <fstream>
#include <iostream>
#include <unordered_set>
#include <vector>

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

ABSL_FLAG(std::vector<std::string>, targets, std::vector<std::string>{},
          "Outputs of flashroute. If there are multiple files, split by comma.");

ABSL_FLAG(std::string, prefix, "", "Prefix of the path to the output file");
ABSL_FLAG(int, start, 0, "Starting index of the outputs");
ABSL_FLAG(int, end, 0, "Ending index of the outputs");

struct DataElement {
  uint32_t destination[4];
  uint32_t responder[4];
  uint32_t rtt;
  uint8_t distance;
  uint8_t fromDestination;
  uint8_t ipv4;
} __attribute__((packed));;

using EdgeMap = std::unordered_map<
    IpAddress *, std::shared_ptr<std::unordered_map<uint32_t, IpAddress *>>,
    IpAddressHash, IpAddressEquality>;
void cleanEdgeMap(EdgeMap& map) {
    while (!map.empty()) {
      auto element = map.begin();
      auto keyAddress = element->first;
      auto routeMap = element->second;
      while (!routeMap->empty()) {
        auto pair = routeMap->begin();
        delete pair->second;
        routeMap->erase(pair->first);
      }
      map.erase(keyAddress);
      delete keyAddress;
    }
}

int main(int argc, char* argv[]) {
  FLAGS_alsologtostderr = 1;
  google::InitGoogleLogging(argv[0]);
  absl::SetProgramUsageMessage("This program does nothing.");
  absl::ParseCommandLine(argc, argv);


  std::unordered_set<IpAddress *, IpAddressHash, IpAddressEquality> observedInterface;

  EdgeMap observedEdges;
  std::unordered_set<uint64_t> edges;

  std::ifstream inFile;
  std::vector<std::string> targetFiles;
  if (absl::GetFlag(FLAGS_targets).size() != 0) {
    targetFiles = absl::GetFlag(FLAGS_targets);
  } else if (!absl::GetFlag(FLAGS_prefix).empty()){
    int start = absl::GetFlag(FLAGS_start);
    int end =
        absl::GetFlag(FLAGS_end) == 0 ? start + 1 : absl::GetFlag(FLAGS_end);
    for (int i = start; i < end; i++) {
      targetFiles.push_back(absl::GetFlag(FLAGS_prefix) + std::to_string(i));
    }
  } else{
    LOG(ERROR) << "No valid input.";
  }
  uint64_t records = 0;
  uint64_t interface = 0;
  uint64_t previousInterface = 0;
  uint64_t previousEdge = 0;

  for (auto file : targetFiles) {
    LOG(INFO) << "Start to read data from: " << file;
    inFile.open(file, std::ios::in | std::ios::binary);
    DataElement buffer;
    std::unordered_map<
        IpAddress *, std::shared_ptr<std::unordered_map<uint32_t, IpAddress *>>,
        IpAddressHash, IpAddressEquality>
        observedEdges;
    while (inFile.peek() != EOF) {
      inFile.read(reinterpret_cast<char *>(&buffer), 39);
      records++;
      if (buffer.ipv4 == 1) {
        // IPv4 address handling.
        auto addr = new Ipv4Address(buffer.responder[0]);
        if (buffer.fromDestination == true) {
          // Do nothing
        } else if (observedInterface.find(addr) == observedInterface.end()) {
          observedInterface.insert(addr);
          if (buffer.fromDestination == 0)
            interface += 1;

        } else {
          delete addr;
        }
        auto dest = new Ipv4Address(buffer.destination[0]);
        if (observedEdges.find(dest) == observedEdges.end()) {
          auto tmp = std::make_shared<std::unordered_map<uint32_t, IpAddress *>>();
          observedEdges.insert({dest, tmp});
        }
        auto tmp = observedEdges.find(dest)->second;
        if (tmp->find(buffer.distance) == tmp->end()) {
          tmp->insert({buffer.distance, new Ipv4Address(buffer.responder[0])});
        }
      } else {
        // IPv6 address handling
        // TODO: we need to add the code logic handle IPv6 Address.
      }
    }
    inFile.clear();
    inFile.seekg(0);
    inFile.close();
    for (const auto &key : observedEdges) {
      auto route = key.second;
      uint64_t edge = 0;
      for (const auto &node : *route) {
        if (route->find(node.first - 1) != route->end()) {
          uint64_t current = node.second->getIpv4Address();
          uint64_t previous =
              route->find(node.first - 1)->second->getIpv4Address();
          edge = previous | current >> 32;
          edges.insert(edge);
        }
      }
    }
    cleanEdgeMap(observedEdges);
    LOG(INFO) << "Unique interface: " << interface << "(+"
              << interface - previousInterface
              << ") Unique edges: " << edges.size() << "(+"
              << edges.size() - previousEdge << ")";
    previousInterface = interface;
    previousEdge = edges.size();
  }

  LOG(INFO) << "Processed " << records << " records.";
  LOG(INFO) << "There are " << interface << " unique interfaces.";
  LOG(INFO) << "There are " << edges.size() << " unique edges.";

}
