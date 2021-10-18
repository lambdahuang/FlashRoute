#include <fstream>
#include <unordered_map>
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
#include "flashroute/utils.h"
#include "parsers/utils/utils.h"

ABSL_FLAG(std::string, directory, "", "Path to the directory of output files");
ABSL_FLAG(std::string, label, "", "Label of the data set");
ABSL_FLAG(int, start, 0, "Starting index of the outputs");
ABSL_FLAG(int, end, 0, "Ending index of the outputs");
ABSL_FLAG(int, step, 1, "Step to read outputs");
ABSL_FLAG(int, offset, 0, "Comparing offset");
ABSL_FLAG(int, level, 0, "Comparing level 0 weak 1 medium 2 strong");
ABSL_FLAG(bool, formatted, false, "Output machine-readable format.");
ABSL_FLAG(std::string, output, "", "Directory of output");

using flashroute::IpAddress;
using flashroute::IpAddressEquality;
using flashroute::IpAddressHash;
using flashroute::Ipv4Address;

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
  auto mn2 = m1->find(position + 1);
  auto mn3 = m1->find(position + 2);

  auto mm1 = m2->find(position);
  auto mm2 = m2->find(position + 1);
  auto mm3 = m2->find(position + 2);

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

int main(int argc, char *argv[]) {
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
  switch (absl::GetFlag(FLAGS_level)) {
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

    RouteFullMap routeFullMap1;
    RouteFullMap routeFullMap2;

    std::unordered_map<uint32_t, std::shared_ptr<RouteNodev4>> routeMap1;
    readDataset(set1, routeFullMap1, routeMap1);

    // readDataset(set2, routeFullMap2);
    int similarRoute = 0;
    for (const auto &p : routeMap1) {
      uint32_t dest = p.first;
      uint32_t addr = p.second->address;
      uint32_t dist = p.second->distances[dest];

      std::vector<Routev4> routes;
      std::vector<RouteConstructNodev4> route;
      std::unordered_set<uint32_t> visited;

      findRouteBack(addr, dest, route, routes, visited, routeFullMap1, 0);
      LOG(INFO) << "Destination: " << flashroute::parseIpv4FromIntToString(dest)
                << " Distance: " << static_cast<uint32_t>(dist);
      LOG(INFO) << "Find routes:" << routes.size();
      int i = 0;
      for (auto& r: routes) {
        LOG(INFO) << "Route #" << ++i;
        LOG(INFO) << "Acyclic: "
                  << (r.routeType == RouteType::Acyclic ? "True" : "False");
        LOG(INFO) << "Convergence: "
                  << static_cast<uint32_t>(r.convergencePoint);
        for(auto& n : r.route) {
          LOG(INFO) << "Address:"
                    << flashroute::parseIpv4FromIntToString(n.address)
                    << " Destination:"
                    << flashroute::parseIpv4FromIntToString(n.destination)
                    << " Distance:" << static_cast<uint32_t>(n.distance);
        }
        getchar();
      }
    }

    LOG(INFO) << "Route map size: " << routeFullMap1.size();
    // LOG(INFO) << "Similar/All: " << similarRoute << "/"
    //           << std::max(edgeMap2.size(), edgeMap1.size());
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }
}