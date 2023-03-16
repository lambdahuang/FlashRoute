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
ABSL_FLAG(int, offset, 0, "Comparing offset");
ABSL_FLAG(bool, formatted, false, "Output machine-readable format.");
ABSL_FLAG(std::string, output, "", "Directory of output");

using flashroute::IpAddress;
using flashroute::Ipv4Address;
using flashroute::IpAddressHash;
using flashroute::IpAddressEquality;

template <typename T>
double JaccardSimilarity(std::unordered_set<T> set1, std::unordered_set<T> set2) {
  uint32_t intersect = 0;
  for (const auto& element : set1) {
    if (set2.find(element) != set2.end())
      intersect++;
  }
  set1.insert(set2.begin(), set2.end());
  return static_cast<double>(intersect) / static_cast<double>(set1.size());
}

int main(int argc, char* argv[]) {
  LOG(INFO) << "Program starts.";
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

  std::vector<std::pair<std::string, std::string>> targetFiles;

  std::string prefix =
      absl::GetFlag(FLAGS_directory) + absl::GetFlag(FLAGS_label) + "_";
  int start = absl::GetFlag(FLAGS_start);
  int end =
      absl::GetFlag(FLAGS_end) == 0 ? start + 1 : absl::GetFlag(FLAGS_end);

  int step = absl::GetFlag(FLAGS_step);
  int offset = absl::GetFlag(FLAGS_offset);
  for (int i = start; i < end; i += step) {
    targetFiles.push_back(
        {prefix + std::to_string(i), prefix + std::to_string(i + offset)});
  }

  double avgInterfaceJaccardIndex = 0;
  double avgEdgeJaccardIndex = 0;
  for (auto combo : targetFiles) {
    std::string set1 = combo.first;
    std::string set2 = combo.second;

    RouteMap edgeMap1;
    RouteMap edgeMap2;
    InterfaceSet interfaceSet1;
    InterfaceSet interfaceSet2;
    readDataset(set1, edgeMap1, interfaceSet1);
    readDataset(set2, edgeMap2, interfaceSet2);

    auto genericEdgeSet1 = edgeMapToGenericEdgeSet(edgeMap1);
    auto genericEdgeSet2 = edgeMapToGenericEdgeSet(edgeMap2);

    auto genericInterfaceSet1 =
        interfaceSetToGenericInterfaceSet(interfaceSet1);
    auto genericInterfaceSet2 =
        interfaceSetToGenericInterfaceSet(interfaceSet2);

    cleanEdgeMap(edgeMap1);
    cleanEdgeMap(edgeMap2);

    cleanInterfaceSet(interfaceSet1);
    cleanInterfaceSet(interfaceSet2);

    auto edgeJaccardIndex = JaccardSimilarity(genericEdgeSet1, genericEdgeSet2);
    auto interfaceJaccardIndex =
        JaccardSimilarity(genericInterfaceSet1, genericInterfaceSet2);

    auto logFilenameSet1 = getLogFileName(absl::GetFlag(FLAGS_directory), set1);
    auto logFilenameSet2 = getLogFileName(absl::GetFlag(FLAGS_directory), set2);
    auto createdTime1 = getStartingTime(logFilenameSet1);
    auto createdTime2 = getStartingTime(logFilenameSet2);

    // LOG(INFO) << "Set1: " << set1 << " Set2: " << set2;
    // LOG(INFO) << "Set1: " << createdTime1 << " Set2: " << createdTime2
    //           << " Edge Jaccard Index: " << edgeJaccardIndex
    //           << " Interface Jaccard Index: " << interfaceJaccardIndex;
    avgInterfaceJaccardIndex += interfaceJaccardIndex;
    avgEdgeJaccardIndex += edgeJaccardIndex;
  }
  LOG(INFO) << " Edge Jaccard Index: " << avgEdgeJaccardIndex/targetFiles.size()
            << " Interface Jaccard Index: " << avgInterfaceJaccardIndex/targetFiles.size();
}