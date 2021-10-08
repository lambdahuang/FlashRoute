#include <fstream>
#include <unordered_set>
#include <unordered_map>

#include "glog/logging.h"
#include "absl/flags/usage.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/str_cat.h"
#include "absl/numeric/int128.h"

#include "flashroute/address.h"
#include "flashroute/dump_result.h"
#include "parsers/utils/utils.h"

ABSL_FLAG(std::string, directory, "", "Path to the directory of output files");
ABSL_FLAG(std::string, label, "", "Label of the data set");
ABSL_FLAG(int, start, 0, "Starting index of the outputs");
ABSL_FLAG(int, end, 0, "Ending index of the outputs");
ABSL_FLAG(int, step, 0, "Step to read outputs");
ABSL_FLAG(bool, formatted, false, "Output machine-readable format.");
ABSL_FLAG(std::string, output, "", "Directory of output");

using flashroute::IpAddress;
using flashroute::Ipv4Address;
using flashroute::IpAddressHash;
using flashroute::IpAddressEquality;

using GenericEdgeMap = std::unordered_map<uint64_t, uint32_t>;
using GenericInterfaceMap = std::unordered_map<uint32_t, uint32_t>;

template <typename T, typename X>
void getFrequencyDistribution(
    std::unordered_map<T, X> input,
    std::unordered_map<uint32_t, uint32_t> &frequency) {
  for (auto &pair : input) {
    auto result = frequency.find(pair.second);
    if (result == frequency.end()) {
      frequency.insert({pair.second, 1});
    } else {
      frequency[pair.second] = result->second + 1;
    }
  }
}

void printFrequency(std::unordered_map<uint32_t, uint32_t> &frequency) {
  LOG(INFO) << "----";
  for (auto& pair: frequency) {
    LOG(INFO) << pair.first << " " << pair.second;
  }
}

int main(int argc, char* argv[]) {
  LOG(INFO) << "Program starts.";
  FLAGS_alsologtostderr = 1;
  absl::SetProgramUsageMessage("This program does nothing.");
  absl::ParseCommandLine(argc, argv);

  std::string logOutput =
      absl::GetFlag(FLAGS_output) + absl::GetFlag(FLAGS_label) +
      std::to_string(absl::GetFlag(FLAGS_start)) + "_" +
      std::to_string(absl::GetFlag(FLAGS_end)) + "_frequency_analysis_log";

  google::InitGoogleLogging(argv[0]);
  if (!absl::GetFlag(FLAGS_output).empty()) {
    google::SetLogDestination(0, logOutput.c_str());
  }

  std::vector<std::string> targetFiles;

  std::string prefix =
      absl::GetFlag(FLAGS_directory) + absl::GetFlag(FLAGS_label) + "_";
  int start = absl::GetFlag(FLAGS_start);
  int end =
      absl::GetFlag(FLAGS_end) == 0 ? start + 1 : absl::GetFlag(FLAGS_end);

  int step = absl::GetFlag(FLAGS_step);
  for (int i = start; i < end; i += step) {
    targetFiles.push_back(prefix + std::to_string(i));
  }

  int datasetCount = 0;
  GenericEdgeMap frequencyEdgeMap;
  GenericInterfaceMap frequencyInterfaceMap;
  for (auto& dataset : targetFiles) {

    RouteMap edgeMap;
    InterfaceSet interfaceSet;
    readDataset(dataset, edgeMap, interfaceSet);

    auto genericEdgeSet = edgeMapToGenericEdgeSet(edgeMap);
    auto genericInterfaceSet = interfaceSetToGenericInterfaceSet(interfaceSet);

    cleanEdgeMap(edgeMap);
    cleanInterfaceSet(interfaceSet);

    auto logFilename = getLogFileName(absl::GetFlag(FLAGS_directory), dataset);
    auto createdTime = getStartingTime(logFilename);

    // Add edge to generic edge set and update its frequency
    for (auto edge : genericEdgeSet) {
      auto result = frequencyEdgeMap.find(edge);
      if (result == frequencyEdgeMap.end()) {
        frequencyEdgeMap.insert({edge, 1});
      } else {
        frequencyEdgeMap[edge] = result->second + 1;
      }
    }

    // Add interface to generic interface set and update its frequency
    for (auto interface : genericInterfaceSet) {
      auto result = frequencyInterfaceMap.find(interface);
      if (result == frequencyInterfaceMap.end()) {
        frequencyInterfaceMap.insert({interface, 1});
      } else {
        frequencyInterfaceMap[interface] = result->second + 1;
      }
    }
    datasetCount += 1;
    LOG(INFO) << datasetCount << " " << logFilename;
  }

  std::unordered_map<uint32_t, uint32_t> edgeFrequencyDistribution;
  std::unordered_map<uint32_t, uint32_t> interfaceFrequencyDistribution;

  getFrequencyDistribution(frequencyEdgeMap, edgeFrequencyDistribution);
  getFrequencyDistribution(frequencyInterfaceMap,
                           interfaceFrequencyDistribution);
  printFrequency(edgeFrequencyDistribution);
  printFrequency(interfaceFrequencyDistribution);
}