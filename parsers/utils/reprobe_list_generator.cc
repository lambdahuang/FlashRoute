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
#include "absl/strings/str_split.h"
#include "glog/logging.h"

#include "flashroute/address.h"
#include "flashroute/dump_result.h"
#include "parsers/utils/utils.h"

using flashroute::IpAddress;
using flashroute::IpAddressEquality;
using flashroute::IpAddressHash;
using flashroute::Ipv4Address;

using FlowIdentityHopMapType = std::map<uint64_t, uint8_t>;

using ProbeMapType =
    std::unordered_map<uint32_t, std::unique_ptr<FlowIdentityHopMapType>>;

using EdgeMapType =
    std::unordered_map<uint32_t,
                       std::unique_ptr<std::unordered_map<uint32_t, uint32_t>>>;

using RouteMapType =
    std::unordered_map<uint32_t, std::unique_ptr<std::map<uint8_t, uint32_t>>>;

using NewProbeTargetMapType = std::unordered_map<uint64_t, uint8_t>;

using NonstopInterfaceSetType = std::unordered_set<uint32_t>;

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
ABSL_FLAG(bool, use_random_address, false,
          "Generate random addresses if not enough reprobe candidate.");
ABSL_FLAG(bool, show_statistic, false,
          "Show distribution of reprobe interfaces on hops");
ABSL_FLAG(std::string, output, "reprobe_list", "Directory of output");
ABSL_FLAG(std::string, previous_reprobe, "", "Previous reprobe list");
ABSL_FLAG(int, response_hop_gap_distance, 1, "Previous reprobe list");

static uint64_t generateRandomFlowLabel(uint32_t addr) {
  uint16_t newPort = rand() % 50000 + 10000;
  return static_cast<uint64_t>(addr) << 32 | newPort;
}

static uint32_t generateRandomAddress(uint32_t addr, int prefix,
                                      int subnetSize) {
  uint32_t newAddr;
  do {
    newAddr = (addr << (32 - prefix)) + (rand() % (subnetSize - 3)) + 2;
  } while (newAddr == addr);
  return newAddr;
}

static uint32_t ipStringToInteger(const std::string &stringIp) {
  return ntohl(inet_addr(stringIp.c_str()));
}

static std::string numericalToStringIp(uint32_t ip) {
  struct in_addr ip_addr;
  ip_addr.s_addr = ip;
  std::string address(inet_ntoa(ip_addr));
  return address;
}

static void readReprobeList(std::string filePath, NewProbeTargetMapType &list) {
  if (filePath.empty()) {
    return;
  }

  std::ifstream in(filePath);
  int64_t count = 0;
  for (std::string line; std::getline(in, line);) {
    if (!line.empty()) {
      // Example
      // 127.0.0.1:10:12345   IPAddress is 127.0.0.1 and split ttl is 10, and
      // source port is 12345
      std::vector<absl::string_view> parts = absl::StrSplit(line, ":");
      auto destination = ipStringToInteger(std::string(parts[0]));
      int splitTtl = 16;
      uint32_t sourcePort = 0;
      if (parts.size() > 1) {
        if (!absl::SimpleAtoi(parts[1], &splitTtl)) {
          return;
        }
      }
      if (parts.size() > 2) {
        if (!absl::SimpleAtoi(parts[2], &sourcePort)) {
          return;
        }
      }
      uint64_t newFlowIdentity =
          static_cast<uint64_t>(destination) << 32 | sourcePort;
      if (list.find(newFlowIdentity) == list.end()) {
        list.insert({newFlowIdentity, splitTtl});
      }
    }
  }
  in.close();
  LOG(INFO) << "Load " << count << " addresses from file.";
}

static void
calculateTargetResponseRate(NewProbeTargetMapType &list,
                            std::unordered_set<uint64_t> &respondedDestination,
                            uint64_t flowId, uint8_t hop) {
  if (respondedDestination.find(flowId) != respondedDestination.end()) {
    return;
  }
  auto result = list.find(flowId);
  if (result != list.end()) {
    uint8_t plannedHop = result->second;
    if (plannedHop - hop >= 0 &&
        plannedHop - hop <= absl::GetFlag(FLAGS_response_hop_gap_distance)) {
      respondedDestination.insert(flowId);
    }
  }
}

static void dumpReprobeList(std::string output, NewProbeTargetMapType &list) {
  std::ofstream dumpFile(output);
  for (auto &record : list) {
    std::string ipAddress = numericalToStringIp(record.first >> 32);
    uint16_t sourcePort = static_cast<uint16_t>(record.first & 0xFFFF);
    int hopDistance = record.second;
    dumpFile << ipAddress << ":" << hopDistance << ":" << sourcePort
             << std::endl;
  }
  dumpFile.close();
}

static void dumpNonstopList(std::string output, NonstopInterfaceSetType &list) {
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

static std::pair<uint8_t, uint8_t>
getMediaHopDistanceFromVantagePoint(FlowIdentityHopMapType &destinationToHop,
                                    RouteMapType &routeMap) {
  std::multiset<uint8_t> distancesToVantagePoint;
  std::multiset<uint8_t> distancesToDestination;
  for (auto &pair : destinationToHop) {
    uint32_t destination = static_cast<uint32_t>(pair.first >> 32);
    uint16_t port = static_cast<uint32_t>(pair.first & 0xFFFF);
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

static void
interfaceDemographicAnalysis(ProbeMapType &probeMap, RouteMapType &routeMap,
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

  NewProbeTargetMapType previousToProbeMap;
  std::unordered_set<uint64_t> respondedDestination;
  if (!absl::GetFlag(FLAGS_previous_reprobe).empty()) {
    readReprobeList(absl::GetFlag(FLAGS_previous_reprobe), previousToProbeMap);
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

  // {Interface, {Destination:SourcePort, hopDistance}}
  ProbeMapType probeMap;

  // {interface, (hop-1) <interfaces, num of observations>}
  EdgeMapType edgeMap;

  // {Destination, backward probe start hop}
  NewProbeTargetMapType toProbeMap;

  // {Destination}
  NonstopInterfaceSetType nonstopInterfaces;

  // {desination, {hopDistance, interface}}
  RouteMapType routeMap;

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
      inFile.read(reinterpret_cast<char *>(&buffer), sizeof(DataElement));
      records++;

      if (buffer.ipv4 == 1) {
        // IPv4 address handling.
        auto isIpv4 = buffer.ipv4;
        auto isFromDestination = buffer.fromDestination;
        uint32_t interface = buffer.responder[0];
        uint32_t destination = buffer.destination[0];
        uint8_t hopDistance = buffer.distance;
        uint16_t sourcePort = buffer.sourcePort;
        // Update ProbeMap
        // if isFromDestination == true, it is from the destination instead of
        // intermediate router interface, so we don't add it to the list.
        if (isFromDestination == true)
          continue;

        // Last file
        if (file == *targetFiles.rbegin() && !previousToProbeMap.empty()) {
          calculateTargetResponseRate(
              previousToProbeMap, respondedDestination,
              (static_cast<uint64_t>(destination) << 32 | sourcePort),
              hopDistance);
        }
        auto interfaceRecord = probeMap.find(interface);
        FlowIdentityHopMapType *probeMapRecord;
        if (interfaceRecord == probeMap.end()) {
          probeMapRecord = new FlowIdentityHopMapType();
          probeMap.insert({interface, std::unique_ptr<FlowIdentityHopMapType>(
                                          probeMapRecord)});
        } else {
          probeMapRecord = interfaceRecord->second.get();
        }
        probeMapRecord->insert(
            {static_cast<uint64_t>(destination) << 32 | sourcePort,
             hopDistance});

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
      nonstopInterfaces.insert(interface);
      // Consider the upper link can be reprobed.
      identifiedReprobeInterfaces++;
      // Select the bullets to probe
      auto candidates = *(probeMap.find(interface)->second);
      uint32_t reprobeCandidate = 0;
      // if the destination does not probe any lesser
      for (auto &candidate : candidates) {
        uint32_t destination = candidate.first >> 32;
        uint64_t candidateFlowIdentity = candidate.first;
        uint8_t candidateExpectedProbeHop = candidate.second - 1;
        if (candidateExpectedProbeHop <= 1)
          continue;
        auto route = *(routeMap.find(destination)->second);
        if (route.find(candidateExpectedProbeHop) != route.end())
          continue;
        auto toProbeRecord = toProbeMap.find(destination);
        if (toProbeRecord != toProbeMap.end())
          // toProbeRecord->second /* hop */ >= candidateExpectedProbeHop)
          continue;
        reprobeCandidate++;
        toProbeMap.insert(
            {candidateFlowIdentity, candidateExpectedProbeHop + 1});
        // Now we consider this candidate can be added
        if (expectProbe(totalDiscoveredInterfaces) <=
            totalProbeTimes + reprobeCandidate)
          break;
      }

      int gap = expectProbe(totalDiscoveredInterfaces) - totalProbeTimes -
                reprobeCandidate;
      // if probes are not enough after selection, we create new flow
      // identities.
      if (gap <= 0) {
        identifiedFullyCoveredReprobeInterfaces++;
      } else if (absl::GetFlag(FLAGS_use_random_address)) {
        randomGeneratedReprobeInterfaces++;
        // Select the random addresses
        for (auto &candidate : candidates) {
          uint32_t destination = candidate.first >> 32;
          uint32_t candidateAddr =
              generateRandomAddress(destination, prefixLength, subnetSize);
          uint8_t candidateExpectedProbeHop = candidate.second - 1;
          reprobeCandidate++;
          toProbeMap.insert({static_cast<uint64_t>(candidateAddr) << 32,
                             candidateExpectedProbeHop + 1});
          // Now we consider this candidate can be added
          if (expectProbe(totalDiscoveredInterfaces) <=
              totalProbeTimes + reprobeCandidate)
            break;
        }
      } else {
        // Use random flow labels
        for (int i = 0; i < gap; i++) {
          auto it = candidates.begin();
          std::advance(it, rand() % (candidates.size()));
          uint32_t destination = it->first >> 32;
          uint16_t sourcePort = it->first & 0xFFFF;
          uint64_t newFlowIdentity = generateRandomFlowLabel(destination);
          uint8_t candidateExpectedProbeHop = it->second - 1;
          if (toProbeMap.find(newFlowIdentity) == toProbeMap.end()) {
            toProbeMap.insert({newFlowIdentity, candidateExpectedProbeHop + 1});
          }
        }
      }
    }
  }
  if (absl::GetFlag(FLAGS_show_statistic)) {
    interfaceDemographicAnalysis(probeMap, routeMap, nonstopInterfaces);
  }
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

    if (!previousToProbeMap.empty()) {
      LOG(INFO) << " Last Reprobe Responded FlowId Number: "
                << respondedDestination.size();

      LOG(INFO) << " Previous Reprobe List Size: " << previousToProbeMap.size();

      LOG(INFO) << " Last Reprobe Responding Rate "
                << static_cast<float>(respondedDestination.size()) /
                       previousToProbeMap.size() * 100
                << "%";
    }

  } else {
  }
}
