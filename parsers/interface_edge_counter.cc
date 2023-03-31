#include <cstddef> // for std::size_t -> is a typedef on an unsinged int
#include <cstring> // for std::strlen
#include <fstream>
#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/flags/usage.h"
#include "absl/strings/str_cat.h"
#include "glog/logging.h"

struct DataElement {
  uint32_t destination;
  uint32_t responder;
  uint8_t distance;
  uint8_t fromDestination;
  uint32_t rtt;
  uint8_t probePhase;
  // Packet meta data.
  uint16_t replyIpid;
  uint8_t replyTtl;
  uint16_t replySize;
  uint16_t probeSize;
  uint16_t probeIpid;
  uint16_t probeSourcePort;
  uint16_t probeDestinationPort;
} __attribute__((packed));

ABSL_FLAG(
    std::vector<std::string>, targets, std::vector<std::string>{},
    "Outputs of flashroute. If there are multiple files, split by comma.");

// Example:
// bazel run parsers/utils/unique_interface_counter -- --directory
// /data/directory/ --label 7_25_fast_scan --start 1 --end 100
// --step 5 --formatted true --output ~/prefix_

ABSL_FLAG(std::string, directory, "", "Path to the directory of output files");
ABSL_FLAG(std::string, label, "", "Label of the data set");
ABSL_FLAG(int, start, 0, "Starting index of the outputs");
ABSL_FLAG(int, end, 0, "Ending index of the outputs");
ABSL_FLAG(int, step, 1, "Step to read outputs");
ABSL_FLAG(bool, formatted, false, "Output machine-readable format.");
ABSL_FLAG(std::string, output, "", "Directory of output");

using EdgeMap =
    std::unordered_map<uint32_t,
                       std::shared_ptr<std::unordered_map<uint32_t, uint32_t>>>;
void cleanEdgeMap(EdgeMap &map) {
  while (!map.empty()) {
    auto element = map.begin();
    auto keyAddress = element->first;
    auto routeMap = element->second;
    while (!routeMap->empty()) {
      auto pair = routeMap->begin();
      routeMap->erase(pair->first);
    }
    map.erase(keyAddress);
  }
}

int main(int argc, char *argv[]) {
  FLAGS_alsologtostderr = 1;
  absl::SetProgramUsageMessage("This program does nothing.");
  absl::ParseCommandLine(argc, argv);

  std::string logOutput = absl::GetFlag(FLAGS_output) +
                          absl::GetFlag(FLAGS_label) +
                          std::to_string(absl::GetFlag(FLAGS_start)) + "_" +
                          std::to_string(absl::GetFlag(FLAGS_end)) + "_log";

  google::InitGoogleLogging(argv[0]);
  if (!absl::GetFlag(FLAGS_output).empty()) {
    google::SetLogDestination(0, logOutput.c_str());
  }

  std::unordered_set<uint32_t> observedInterface;

  EdgeMap observedEdges;
  std::unordered_set<uint64_t> edges;

  std::ifstream inFile;
  std::vector<std::string> targetFiles;
  if (absl::GetFlag(FLAGS_targets).size() != 0) {
    targetFiles = absl::GetFlag(FLAGS_targets);
  } else if (!absl::GetFlag(FLAGS_label).empty() &&
             !absl::GetFlag(FLAGS_directory).empty()) {
    std::string prefix =
        absl::GetFlag(FLAGS_directory) + absl::GetFlag(FLAGS_label) + "_";
    int start = absl::GetFlag(FLAGS_start);
    int end =
        absl::GetFlag(FLAGS_end) == 0 ? start + 1 : absl::GetFlag(FLAGS_end);
    for (int i = start; i < end; i += absl::GetFlag(FLAGS_step)) {
      targetFiles.push_back(prefix + std::to_string(i));
    }
  } else {
    LOG(ERROR) << "No valid input.";
  }
  uint64_t records = 0;
  uint64_t interface = 0;
  uint64_t previousInterface = 0;
  uint64_t previousEdge = 0;

  for (auto file : targetFiles) {
    if (!absl::GetFlag(FLAGS_formatted)) {
      LOG(INFO) << "Start to read data from: " << file;
    }

    inFile.open(file, std::ios::in | std::ios::binary);
    DataElement buffer;
    std::unordered_map<uint32_t,
                       std::shared_ptr<std::unordered_map<uint32_t, uint32_t>>>
        observedEdges;
    while (inFile.peek() != EOF) {
      inFile.read(reinterpret_cast<char *>(&buffer), 28);
      records++;
      auto addr = buffer.responder;
      if (buffer.fromDestination == true) {
        // Do nothing
      } else if (observedInterface.find(addr) == observedInterface.end()) {
        observedInterface.insert(addr);
        if (buffer.fromDestination == 0)
          interface += 1;
      }
      auto dest = buffer.destination;
      if (observedEdges.find(dest) == observedEdges.end()) {
        auto tmp = std::make_shared<std::unordered_map<uint32_t, uint32_t>>();
        observedEdges.insert({dest, tmp});
      }
      auto tmp = observedEdges.find(dest)->second;
      if (tmp->find(buffer.distance) == tmp->end()) {
        uint32_t responder = buffer.responder;
        tmp->insert({buffer.distance, responder});
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
          uint64_t current = node.second;
          uint64_t previous = route->find(node.first - 1)->second;
          edge = previous | current >> 32;
          edges.insert(edge);
        }
      }
    }
    cleanEdgeMap(observedEdges);
    if (!absl::GetFlag(FLAGS_formatted)) {
      LOG(INFO) << " Unique interface: " << interface << "(+"
                << interface - previousInterface
                << ") Unique edges: " << edges.size() << "(+"
                << edges.size() - previousEdge << ")";
    } else {
      LOG(INFO) << interface << " " << interface - previousInterface << " "
                << edges.size() << " " << edges.size() - previousEdge;
    }
    previousInterface = interface;
    previousEdge = edges.size();
  }

  LOG(INFO) << "Processed " << records << " records.";
  LOG(INFO) << "There are " << interface << " unique interfaces.";
  LOG(INFO) << "There are " << edges.size() << " unique edges.";
}