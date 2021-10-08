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
ABSL_FLAG(int, level, 0, "Comparing level 0 weak 1 medium 2 strong");
ABSL_FLAG(bool, formatted, false, "Output machine-readable format.");
ABSL_FLAG(std::string, output, "", "Directory of output");

using flashroute::IpAddress;
using flashroute::Ipv4Address;
using flashroute::IpAddressHash;
using flashroute::IpAddressEquality;

using GenericEdgeMap = std::unordered_map<uint64_t, uint32_t>;
using GenericInterfaceMap = std::unordered_map<uint32_t, uint32_t>;

enum class ComparisonLevel { STRONG, MEDIUM, WEAK };

int getLength(
    const std::shared_ptr<std::unordered_map<int8_t, IpAddress *>> &m1) {
  for (int i = 32; i >= 0; i--) {
    if (m1->find(i) != m1->end())
      return i;
  }
  return 0;
}

bool triNodeComparison(
    const std::shared_ptr<std::unordered_map<int8_t, IpAddress *>> &m1,
    const std::shared_ptr<std::unordered_map<int8_t, IpAddress *>> &m2,
    int8_t position, ComparisonLevel comp) {

  auto mn1 = m1->find(position);
  auto mn2 = m1->find(position+1);
  auto mn3 = m1->find(position+2);

  auto mm1 = m2->find(position);
  auto mm2 = m2->find(position+1);
  auto mm3 = m2->find(position+2);


  if (mn1 == m1->end())
    return false;
  // if (mn1 == m1->end() || mn3 == m1->end())
  //   return false;
  // if (mm1 == m1->end() || mm3 == m1->end())
  //   return false;
  // if (mm1->second->getIpv4Address() != mn1->second->getIpv4Address() ||
  //     mm3->second->getIpv4Address() != mn3->second->getIpv4Address())
  //   return false;

  // if (comp == ComparisonLevel::WEAK) {
  //   if (mm2 == m2->end() || mn2 == m1->end()) {
  //     return true;
  //   }

  // } else if (comp == ComparisonLevel::MEDIUM) {
  //   if ((mm2 == m2->end() && mn2 == m1->end()) ||
  //       ((mm2 != m2->end() && mn2 != m1->end()) &&
  //        *(mm2->second) == *(mn2->second))) {
  //     return true;
  //   }
  // } else {
  //   if (((mm2 != m2->end() && mn2 != m1->end()) &&
  //        *(mm2->second) == *(mn2->second))) {
  //     return true;
  //   }
  // }
  return true;
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

  ComparisonLevel level;
  switch (absl::GetFlag(FLAGS_level))
  {
  case 0:
    level = ComparisonLevel::WEAK;
    break;
  case 1:
    level = ComparisonLevel::MEDIUM;
  case 2:
    level = ComparisonLevel::STRONG;
  };

  for (auto combo : targetFiles) {

    LOG(INFO) << combo.first;
    LOG(INFO) << combo.second;
    std::string set1 = combo.first;
    std::string set2 = combo.second;

    RouteMap edgeMap1;
    RouteMap edgeMap2;
    InterfaceSet interfaceSet1;
    InterfaceSet interfaceSet2;
    readDataset(set1, edgeMap1, interfaceSet1);
    readDataset(set2, edgeMap2, interfaceSet2);
    int similarRoute = 0;

    for (const auto& elem : edgeMap1) {
        auto dest = elem.first;
        auto route1 = elem.second;
        auto tmp = edgeMap2.find(dest); 
        if(tmp == edgeMap2.end()) continue;
        auto route2 = tmp->second;
        if (route1->size() > 5) similarRoute++;
        // LOG(INFO) << "*" << route1->size() << " *" << route2->size();

        // for(const auto& ele : *route1) {
        //   LOG(INFO) << int(ele.first) << " - " << ele.second->getIpv4Address();
        // }

        // int len0 = getLength(route1);
        // int len1 = getLength(route2);
        // bool similar = true;
        // if (len0 == len2) {
        //   int s = -1;
        //   for (int i = -1; i < len1 - 3; i++) {
        //     if (triNodeComparison(route0, route2, i, level)) {
        //       s++;
        //     }
        //   }
        //   LOG(INFO) << s << "/" << len0 - 3;
        //   if ((static_cast<double>(s) / static_cast<double>(len0 - 3)) > 0.75)
        //     similar = true;
        //   else
        //     similar = false;
        // } else {
        //   similar = false;
        // }
        // if (similar == true) similarRoute ++;


    }
    LOG(INFO) << "Similar/All: " << similarRoute << "/"
              << std::max(edgeMap2.size(), edgeMap1.size());
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }

}