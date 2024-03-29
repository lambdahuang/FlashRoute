#include <cstddef> // for std::size_t -> is a typedef on an unsinged int
#include <cstring> // for std::strlen
#include <fstream>
#include <iostream>
#include <map>
#include <set>
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
ABSL_FLAG(int, prefix, 24,
          "Prefix length, which is used to generate candidate addresses.");
ABSL_FLAG(int, start, 0, "Starting index of the outputs");
ABSL_FLAG(int, end, 0, "Ending index of the outputs");
ABSL_FLAG(int, step, 1, "Step to read outputs");
ABSL_FLAG(float, threshold, 2, "Hot branch threshold");
ABSL_FLAG(bool, formatted, false, "Output machine-readable format.");
ABSL_FLAG(std::string, output, "reprobe_list", "Directory of output");

static uint32_t generateRandomAddress(uint32_t addr, int prefix,
                                      int subnetSize) {
  uint32_t newAddr;
  do {
    newAddr = (addr << (32 - prefix)) + (rand() % (subnetSize - 3)) + 2;
  } while (newAddr == addr);
  return newAddr;
}

static std::string numericalToStringIp(uint32_t ip) {
  struct in_addr ip_addr;
  ip_addr.s_addr = ip;
  std::string address(inet_ntoa(ip_addr));
  return address;
}

static void dumpReprobeList(std::string output,
                            std::unordered_map<uint32_t, uint8_t> &list) {
  std::ofstream dumpFile(output);
  for (auto &record : list) {
    std::string ipAddress = numericalToStringIp(record.first);
    int hopDistance = record.second;
    dumpFile << ipAddress << ":" << hopDistance << std::endl;
  }
  dumpFile.close();
}

static void dumpNonstopList(std::string output,
                            std::unordered_set<uint32_t> &list) {
  std::ofstream dumpFile(output);
  for (auto &record : list) {
    std::string ipAddress = numericalToStringIp(record);
    dumpFile << ipAddress << std::endl;
  }
  dumpFile.close();
}

static int expectProbe(int n) {
  static int probeTable[] = {
      /*0*/ 0,   /*1*/ 0,   /*2*/ 6,   /*3*/ 11,  /*4*/ 16,
      /*5*/ 21,  /*6*/ 27,  /*7*/ 33,  /*8*/ 38,
      /*9*/ 44,  /*10*/ 51, /*11*/ 57, /*12*/ 63, /*13*/ 70,
      /*14*/ 76, /*15*/ 83, /*16*/ 90, /*17*/ 96};
  if (n < 2) {
    return 2;
  } else if (n > 18) {
    return 97;
  }
  return probeTable[n];
}

static std::pair<uint8_t, uint8_t> getMediaHopDistanceFromVantagePoint(
    std::map<uint32_t, uint8_t> &destinationToHop,
    std::unordered_map<uint32_t, std::unique_ptr<std::map<uint8_t, uint32_t>>>
        &routeMap) {
  std::multiset<uint8_t> distancesToVantagePoint;
  std::multiset<uint8_t> distancesToDestination;
  for (auto &pair : destinationToHop) {
    uint32_t destination = pair.first;
    uint8_t hop = pair.second;
    auto route = *(routeMap.find(destination))->second;
    distancesToVantagePoint.insert(hop);
    distancesToDestination.insert(route.rbegin()->first - hop + 1);
  }
  std::set<uint8_t>::iterator it1 = distancesToVantagePoint.begin();
  std::advance(it1, distancesToVantagePoint.size() / 2);

  std::set<uint8_t>::iterator it2 = distancesToDestination.begin();
  std::advance(it2, distancesToDestination.size() / 2);
  return {*it1, *it2};
}

static void interfaceDemographicAnalysis(
    std::unordered_map<uint32_t, std::unique_ptr<std::map<uint32_t, uint8_t>>>
        &probeMap,
    std::unordered_map<uint32_t, std::unique_ptr<std::map<uint8_t, uint32_t>>>
        &routeMap,
    std::unordered_set<uint32_t> &targetInterfaces) {
  std::map<uint8_t, uint32_t> distanceFromVantagePointToCount;
  std::map<uint8_t, uint32_t> distanceFromDestinationToCount;
  for (auto &interface : targetInterfaces) {
    auto it = probeMap.find(interface);
    if (it != probeMap.end()) {
      auto destinationToDistance = *it->second;
      auto result =
          getMediaHopDistanceFromVantagePoint(destinationToDistance, routeMap);
      uint8_t interfaceMediaDistanceFromVantagePoint = result.first;
      uint8_t interfaceMediaDistanceFromDestination = result.second;
      if (distanceFromVantagePointToCount.find(
              interfaceMediaDistanceFromVantagePoint) !=
          distanceFromVantagePointToCount.end()) {
        distanceFromVantagePointToCount
            [interfaceMediaDistanceFromVantagePoint]++;
      } else {
        distanceFromVantagePointToCount
            [interfaceMediaDistanceFromVantagePoint] = 0;
      }
      if (distanceFromDestinationToCount.find(
              interfaceMediaDistanceFromDestination) !=
          distanceFromDestinationToCount.end()) {
        distanceFromDestinationToCount[interfaceMediaDistanceFromDestination]++;
      } else {
        distanceFromDestinationToCount[interfaceMediaDistanceFromDestination] =
            0;
      }
    }
  }
  for (int i = 0; i < 64; i++) {
    LOG(INFO) << (int)i << " " << distanceFromVantagePointToCount[i] << " "
              << distanceFromDestinationToCount[i];
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

  std::srand(0);
  uint64_t records = 0;
  uint64_t identifiedReprobeInterfaces = 0;
  uint64_t identifiedFullyCoveredReprobeInterfaces = 0;
  uint64_t randomGeneratedReprobeInterfaces = 0;
  uint64_t hotInterface = 0;
  uint32_t totalUniqueEdgeCount = 0;
  int prefixLength = absl::GetFlag(FLAGS_prefix);
  int subnetSize = static_cast<int>(std::pow(2, 32 - prefixLength));

  float threshold = absl::GetFlag(FLAGS_threshold);

  // {Interface, {Destination, hopDistance}}
  std::unordered_map<uint32_t, std::unique_ptr<std::map<uint32_t, uint8_t>>>
      probeMap;

  // {interface, (hop-1) <interfaces, num of observations>}
  std::unordered_map<uint32_t,
                     std::unique_ptr<std::unordered_map<uint32_t, uint32_t>>>
      edgeMap;

  // {Destination, backward probe start hop}
  std::unordered_map<uint32_t, uint8_t> toProbeMap;

  // {Destination}
  std::unordered_set<uint32_t> nonstopInterfaces;

  // {desination, {hopDistance, interface}}
  std::unordered_map<uint32_t, std::unique_ptr<std::map<uint8_t, uint32_t>>>
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
        // if isFromDestination == true, it is from the destination instead of
        // intermediate router interface, so we don't add it to the list.
        if (isFromDestination == true)
          continue;
        auto interfaceRecord = probeMap.find(interface);
        std::map<uint32_t, uint8_t> *probeMapRecord;
        if (interfaceRecord == probeMap.end()) {
          probeMapRecord = new std::map<uint32_t, uint8_t>();
          probeMap.insert(
              {interface,
               std::unique_ptr<std::map<uint32_t, uint8_t>>(probeMapRecord)});
        } else {
          probeMapRecord = interfaceRecord->second.get();
        }
        probeMapRecord->insert({destination, hopDistance});

        // Update Route Map
        auto routeRecord = routeMap.find(destination);
        std::map<uint8_t, uint32_t> *route;
        if (routeRecord == routeMap.end()) {
          route = new std::map<uint8_t, uint32_t>();
          routeMap.insert(
              {destination,
               std::unique_ptr<std::map<uint8_t, uint32_t>>(route)});
        } else {
          route = routeRecord->second.get();
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

    // Update edgeMap: {interface, (hop-1) <interfaces, num of observations>}
    for (const auto &routeRecord : routeMap) {
      uint32_t destination = routeRecord.first;
      int previousHop = -1;
      int previousInterface = -1;
      for (const auto &hopRecord : *routeRecord.second) {
        uint8_t hop = hopRecord.first;
        uint32_t interface = hopRecord.second;

        std::unordered_map<uint32_t, uint32_t> *edges;
        auto edgeRecord = edgeMap.find(interface);
        if (edgeRecord == edgeMap.end()) {
          edges = new std::unordered_map<uint32_t, uint32_t>();
          edgeMap.insert(
              {interface,
               std::unique_ptr<std::unordered_map<uint32_t, uint32_t>>(edges)});
        } else {
          edges = edgeRecord->second.get();
        }

        // {hop, interface}
        if (previousHop != -1 && previousHop == hop - 1) {
          auto previousHopRecord = edges->find(previousInterface);
          if (previousHopRecord == edges->end()) {
            edges->insert({previousInterface, 1});
            totalUniqueEdgeCount++;
          } else {
            (*edges)[previousInterface]++;
          }
        }
        previousHop = hop;
        previousInterface = interface;
      }
    }
    LOG(INFO) << "edges processed finished, start select candidate.";

    if (!absl::GetFlag(FLAGS_formatted)) {
      LOG(INFO) << "Dataset Created " << createdTime << " Processed Records "
                << records;
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
    if (expectProbe(totalDiscoveredInterfaces) == 97) {
      hotInterface++;
    }
    if (expectProbe(totalDiscoveredInterfaces) > totalProbeTimes) {
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
        toProbeMap.insert({candidateAddr, candidateExpectedProbeHop + 1});
        // Now we consider this candidate can be added
        if (expectProbe(totalDiscoveredInterfaces) <=
            totalProbeTimes + reprobeCandidate)
          break;
      }
      if (expectProbe(totalDiscoveredInterfaces) <=
          totalProbeTimes + reprobeCandidate) {
        identifiedFullyCoveredReprobeInterfaces++;
      } else {
        randomGeneratedReprobeInterfaces++;
        nonstopInterfaces.insert(interface);
        // Select the random addresses
        for (auto &candidate : candidates) {
          uint32_t candidateAddr =
              generateRandomAddress(candidate.first, prefixLength, subnetSize);
          uint8_t candidateExpectedProbeHop = candidate.second - 1;
          reprobeCandidate++;
          toProbeMap.insert({candidateAddr, candidateExpectedProbeHop + 1});
          // Now we consider this candidate can be added
          if (expectProbe(totalDiscoveredInterfaces) <=
              totalProbeTimes + reprobeCandidate)
            break;
        }
      }
    }
  }
  interfaceDemographicAnalysis(probeMap, routeMap, nonstopInterfaces);
  dumpReprobeList(absl::GetFlag(FLAGS_output), toProbeMap);
  dumpNonstopList(absl::GetFlag(FLAGS_output) + "_nonstop", nonstopInterfaces);

  if (!absl::GetFlag(FLAGS_formatted)) {
    LOG(INFO) << " ProcessedRecords " << records;
    LOG(INFO) << " Total Interfaces " << edgeMap.size();
    LOG(INFO) << " Unique Edge Count " << totalUniqueEdgeCount;
    LOG(INFO) << " Identified Reprobe Target " << identifiedReprobeInterfaces;
    LOG(INFO) << " Identified Fully Covered Reprobe Target "
              << identifiedFullyCoveredReprobeInterfaces;
    LOG(INFO) << " Random generated  Reprobe Target "
              << randomGeneratedReprobeInterfaces;
    LOG(INFO) << " Planned Targets " << toProbeMap.size();
    LOG(INFO) << " Hot Interface " << hotInterface;
  } else {
  }
}
