#include <cstddef> // for std::size_t -> is a typedef on an unsinged int
#include <cstring> // for std::strlen
#include <fstream>
#include <iostream>
#include <map>
#include <unordered_set>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/flags/usage.h"
#include "absl/numeric/int128.h"
#include "absl/strings/str_cat.h"
#include "glog/logging.h"

#include "flashroute/address.h"
#include "flashroute/dump_result.h"
#include "parsers/utils/utils.h"

using flashroute::IpAddress;
using flashroute::IpAddressEquality;
using flashroute::IpAddressHash;
using flashroute::Ipv4Address;

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
ABSL_FLAG(float, threshold, 2, "Hot branch threshold");
ABSL_FLAG(bool, formatted, false, "Output machine-readable format.");
ABSL_FLAG(std::string, output, "", "Directory of output");

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
  uint64_t identifiedReprobeInterfaces = 0;

  float threshold = absl::GetFlag(FLAGS_threshold);

  // {Interface, {Destination, hopDistance}}
  std::unordered_map<uint32_t, std::shared_ptr<std::map<uint32_t, uint8_t>>>
      probeMap;

  // {interface, (hop-1) <interfaces, num of observations>}
  std::unordered_map<uint32_t,
                     std::shared_ptr<std::unordered_map<uint32_t, uint32_t>>>
      edgeMap;

  // {Destination, backward probe start hop}
  std::unordered_map<uint32_t, uint8_t> toProbeMap;

  // {desination, {hopDistance, interface}}
  std::unordered_map<uint32_t, std::shared_ptr<std::map<uint8_t, uint32_t>>>
      routeMap;

  for (auto file : targetFiles) {
    if (!absl::GetFlag(FLAGS_formatted)) {
      LOG(INFO) << "Start to read data from: " << file;
    }
    auto logFilename = getLogFileName(absl::GetFlag(FLAGS_directory), file);

    auto createdTime = getStartingTime(logFilename);
    inFile.open(file, std::ios::in | std::ios::binary);
    DataElement buffer;

    LOG(INFO) << "start read from file.";
    while (inFile.peek() != EOF) {
      inFile.read(reinterpret_cast<char *>(&buffer), 39);
      records++;

      if (buffer.ipv4 == 1) {
        // IPv4 address handling.
        auto isIpv4 = buffer.ipv4;
        auto isFromDestination = buffer.fromDestination;
        uint32_t interface = buffer.responder[0];
        uint32_t destination = buffer.destination[0];
        uint8_t hopDistance = buffer.distance;
        // Update ProbeMap
        auto interfaceRecord = probeMap.find(interface);
        std::shared_ptr<std::map<uint32_t, uint8_t>> probeMapRecord;
        if (interfaceRecord == probeMap.end()) {
          probeMapRecord = std::make_shared<std::map<uint32_t, uint8_t>>();
          probeMap.insert({interface, probeMapRecord});
        } else {
          probeMapRecord = interfaceRecord->second;
        }
        probeMapRecord->insert({destination, hopDistance});

        // Update Route Map
        auto routeRecord = routeMap.find(destination);
        std::shared_ptr<std::map<uint8_t, uint32_t>> route;
        if (routeRecord == routeMap.end()) {
          route = std::make_shared<std::map<uint8_t, uint32_t>>();
          routeMap.insert({destination, route});
        } else {
          route = routeRecord->second;
        }
        route->insert({hopDistance, interface});

      } else {
        // IPv6 address handling
        // TODO: we need to add the code logic handle IPv6 Address.
      }
    }
    LOG(INFO) << "file read finished.";
    LOG(INFO) << "routes " << routeMap.size();
    inFile.clear();
    inFile.seekg(0);
    inFile.close();

    for (const auto &routeRecord : routeMap) {
      uint32_t destination = routeRecord.first;
      for (const auto &hopRecord : *routeRecord.second) {
        uint8_t hop = hopRecord.first;
        uint32_t interface = hopRecord.second;

        std::shared_ptr<std::unordered_map<uint32_t, uint32_t>> edges;
        auto edgeRecord = edgeMap.find(interface);
        if (edgeRecord == edgeMap.end()) {
          edges = std::make_shared<std::unordered_map<uint32_t, uint32_t>>();
          edgeMap.insert({interface, edges});
        } else {
          edges = edgeRecord->second;
        }

        // {hop, interface}
        auto previousHopRecord = routeRecord.second->find(hop - 1);
        if (previousHopRecord != routeRecord.second->end()) {
          edges->insert({previousHopRecord->second, 1});
        } else {
          (*edges)[previousHopRecord->second]++;
        }
      }
    }
    LOG(INFO) << "edges processed finished, start select candidate.";

    if (!absl::GetFlag(FLAGS_formatted)) {
      LOG(INFO) << "Created " << createdTime;
      LOG(INFO) << " ProcessedRecords " << records;
    } else {
      LOG(INFO) << createdTime;
    }
  }
  // Select candidate
  for (const auto &edges : edgeMap) {
    uint32_t interface = edges.first;
    int totalProbeTimes = 0;
    int totalDiscoveredInterfaces = edges.second->size();
    for (const auto &edge : *edges.second) {
      totalProbeTimes += edge.second;
    }
    if (static_cast<float>(totalProbeTimes) / totalDiscoveredInterfaces <=
        threshold) {
      // Consider the upper link can be reprobed.
      identifiedReprobeInterfaces++;
      // Select the bullets to probe
      auto candidates = *(probeMap.find(interface)->second);
      uint32_t reprobeCandidate = 0;
      // if the destination does not probe any lesser
      for (auto &candidate : candidates) {
        uint32_t candidateAddr = candidate.first;
        uint8_t candidateExpectedProbeHop = candidate.second - 1;
        if (candidateExpectedProbeHop <= 1)
          continue;
        auto route = *(routeMap.find(candidateAddr)->second);
        if (route.find(candidateExpectedProbeHop) != route.end())
          continue;
        auto toProbeRecord = toProbeMap.find(candidateAddr);
        if (toProbeRecord != toProbeMap.end())
          // toProbeRecord->second /* hop */ >= candidateExpectedProbeHop)
          continue;
        reprobeCandidate++;
        toProbeMap.insert({candidateAddr, candidateExpectedProbeHop});
        // Now we consider this candidate can be added
        if (static_cast<float>(totalProbeTimes + reprobeCandidate) /
                totalDiscoveredInterfaces >
            threshold)
          break;
      }
    }
  }
  if (!absl::GetFlag(FLAGS_formatted)) {
    LOG(INFO) << " ProcessedRecords " << records;
    LOG(INFO) << " Total Interfaces " << edgeMap.size();
    LOG(INFO) << " Identified Reprobe Target "
                         << identifiedReprobeInterfaces;
    LOG(INFO) << " Planned Targets " << toProbeMap.size();
  } else {
  }
}
