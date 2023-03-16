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

ABSL_FLAG(std::string, file, "", "Path to the directory of output files");

int main(int argc, char *argv[]) {
  LOG(INFO) << "Program starts.";
  FLAGS_alsologtostderr = 1;
  absl::SetProgramUsageMessage("This program does nothing.");
  absl::ParseCommandLine(argc, argv);

  google::InitGoogleLogging(argv[0]);

  RouteFullMap routeFullMap;
  std::unordered_map<uint32_t, std::shared_ptr<RouteNodev4>> routeMap;
  readDataset(absl::GetFlag(FLAGS_file), routeFullMap, routeMap);
  LOG(INFO) << "Finished";

  int similarRoute = 0;
  std::string buf;
  for (const auto &p : routeMap) {
    uint32_t dest = p.first;
    uint32_t addr = p.second->address;
    uint32_t dist = p.second->distances[dest];

    std::vector<Routev4> routes;
    std::vector<RouteConstructNodev4> route;
    std::unordered_set<uint32_t> visited;

    findRouteBack(addr, dest, route, routes, visited, routeFullMap, 0);
    LOG(INFO) << "Destination: " << flashroute::parseIpv4FromIntToString(dest)
              << " Distance: " << static_cast<uint32_t>(dist);
    LOG(INFO) << "Find routes:" << routes.size();
    int i = 0;
    for (auto &r : routes) {
      LOG(INFO) << "Route #" << ++i << "/" << routes.size();
      LOG(INFO) << "Acyclic: "
                << (r.routeType == RouteType::Acyclic ? "True" : "False");
      LOG(INFO) << "Convergence: " << static_cast<uint32_t>(r.convergencePoint);
      for (auto &n : r.route) {
        LOG(INFO) << "Address:"
                  << flashroute::parseIpv4FromIntToString(n.address)
                  << " Destination:"
                  << flashroute::parseIpv4FromIntToString(n.destination)
                  << " Distance:" << static_cast<uint32_t>(n.distance);
      }
      std::cin >> buf;
      if (buf == "j") {
        break;
      }
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }
}