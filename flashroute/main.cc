/* Copyright (C) 2019 Neo Huang - All Rights Reserved */

#include <csignal>
#include <iostream>
#include <unordered_map>
#include <tuple>

#include "glog/logging.h"
#include <boost/format.hpp>
#include <boost/version.hpp>
#include "absl/flags/usage.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/str_cat.h"

#include "flashroute/blacklist.h"
#include "flashroute/dcb_manager.h"
#include "flashroute/hitlist.h"
#include "flashroute/network.h"
#include "flashroute/targets.h"
#include "flashroute/traceroute.h"
#include "flashroute/udp_prober.h"
#include "flashroute/udp_prober_v6.h"
#include "flashroute/utils.h"
#include "flashroute/single_host.h"
#include "flashroute/output_parser.h"
#include "flashroute/bogon_filter.h"

ABSL_FLAG(bool, recommended_mode, false,
          "Use recommended configuration.");

ABSL_FLAG(bool, sequential_scan, false, "Sequentially scan all targets.");

ABSL_FLAG(std::string, dump_targets_file, "", "Dump targets to file.");

ABSL_FLAG(std::string, prober_type, "udp",
          "The prober used for the scan. Options: udp, udp idempotent");

ABSL_FLAG(int16_t, ttl_offset, 0,
          "Offset of ttl. For example, if offset is 5, the scan will cover the "
          "ttl in thhe range [6, 38].");

ABSL_FLAG(int16_t, split_ttl, 16, "Default split ttl.");
ABSL_FLAG(
    int16_t, granularity, 24,
    "The granularity of scan; that is, scan picks 1 address per the given "
    "length of prefix. The range of this value is [0, 32] for Ipv4 and [0, "
    "128] for Ipv6. By default, 24.");

ABSL_FLAG(std::string, interface, "", "Relay Interface.");
ABSL_FLAG(int32_t, probing_rate, 400000, "Probing rate.");
ABSL_FLAG(std::string, default_payload_message,
          "flashroute",
          "Message embedded in payload of probe.");

// Optimization: Preprobing.
ABSL_FLAG(bool, preprobing, true,
          "Preprobing to collect distances to targets.");
ABSL_FLAG(int16_t, preprobing_ttl, 32, "Preprobing ttl.");

ABSL_FLAG(bool, distance_prediction, true,
          "Distance prediction in preprobing.");

ABSL_FLAG(int32_t, distance_prediction_prefix, 24,
          "Distance prediction will be applied to a given range.");

ABSL_FLAG(int32_t, proximity_span, 5,
          "Proximity span for distnace prediction.");

// Optimization: Forward probing.
ABSL_FLAG(bool, forward_probing, true, "Forward probing to augment scan.");
ABSL_FLAG(int16_t, gaplimit, 5,
          "Max number of consecutive silent hops allowed in forward probing.");

// Optimization: Backward probing.
ABSL_FLAG(bool, remove_redundancy, true,
          "Remove redundancy in backward probing.");

// Optimization: Read route length information from history probing result.

ABSL_FLAG(std::string, history_probing_result, "",
          "Read history result to optimize the coming probing.");

// Miscellaneous

ABSL_FLAG(std::string, bogon_filter_potaroo, "",
          "Bogon filter input in potaroo format.");
ABSL_FLAG(std::string, output, "", "Output path.");

ABSL_FLAG(std::string, tcpdump_output, "", "Tcpdump output path.");
ABSL_FLAG(std::string, hitlist, "", "Hitlist filepath.");
ABSL_FLAG(std::string, targets, "",
              "Target filepath.");

ABSL_FLAG(bool, encode_timestamp, true,
          "Encode timestamp into the packets. Disable this can make the scan "
          "idempotent, in which two scans taking at different times sending "
          "the same set of probes. By defalt, true.");

ABSL_FLAG(bool, remove_reserved_addresses, true,
          "Remove the reserved addresses.");
ABSL_FLAG(std::string, blacklist, "", "Blacklist filepath.");

ABSL_FLAG(uint16_t, dst_port, 33434, "Destination port number.");
ABSL_FLAG(uint16_t, src_port, 53,
          "Source port number (will be overrided if source port field is "
          "required for encoding.)");

ABSL_FLAG(int32_t, seed, 0,
          "Seed for all randomization procedure: including destiantion "
          "generation and probing sequence.");

ABSL_FLAG(int32_t, scan_count, 1, "Number of main scans.");

ABSL_FLAG(bool, verbose, false, "Verbose level 1.");

ABSL_FLAG(bool, vverbose, false, "Verbose level 2.");

using namespace flashroute;

Tracerouter* traceRouterPtr = nullptr;
std::unique_ptr<CommandExecutor> commandExecutor;

std::string finalInterface;

void signalHandler(int signalNumber) {
  LOG(INFO)
      << "Received SIGINT signal. Forcefully terminate program by Ctrl-C.";
  traceRouterPtr->stopScan();
  static bool firstCatch = true;
  if (firstCatch) {
    LOG(INFO) << "Stop probing...";
    firstCatch = false;
  } else {
    commandExecutor->stop();
    LOG(FATAL) << "Forcefully end the program.";
  }
}

void printFlags() {
  VLOG(1) << boost::format("Boost version: %|30t|%1%") % BOOST_LIB_VERSION;

  VLOG(1) << " ========== Network ========== ";
  VLOG(1) << boost::format("Prober Type: %|30t|%1%") %
                 ((absl::GetFlag(FLAGS_prober_type).compare("udp") == 0)
                      ? "udp"
                      : "udp-idempotent");
  VLOG(1) << boost::format("Default Payload Message: %|30t|%1%") %
                   absl::GetFlag(FLAGS_default_payload_message);
  VLOG(1) << boost::format("Interface: %|30t|%1%") % finalInterface;
  VLOG(1) << boost::format("Destination Port: %|30t|%1%") %
                   absl::GetFlag(FLAGS_dst_port);
  VLOG(1) << boost::format("Source Port: %|30t|%1%") %
                   absl::GetFlag(FLAGS_src_port);
  VLOG(1) << boost::format("Sequential Scan: %|30t|%1%") %
                   (absl::GetFlag(FLAGS_sequential_scan) ? "true" : "false");
  VLOG(1) << boost::format("Probing rate: %|30t|%1% Packet Per Second") %
                   absl::GetFlag(FLAGS_probing_rate);

  VLOG(1) << " ========== Experiment Feature ========== ";

  VLOG(1) << boost::format("Scan granularity: %|30t|%1%") %
                   absl::GetFlag(FLAGS_granularity);
  VLOG(1) << boost::format("Preprobing: %|30t|%1%") %
                   (absl::GetFlag(FLAGS_preprobing) ? "true" : "false");
  VLOG(1) << boost::format("Forward probing: %|30t|%1%") %
                   (absl::GetFlag(FLAGS_forward_probing) ? "true" : "false");
  VLOG(1) << boost::format("Forward GapLimit: %|30t|%1%") %
                   absl::GetFlag(FLAGS_gaplimit);
  VLOG(1) << boost::format("Remove Redundancy: %|30t|%1%") %
                   (absl::GetFlag(FLAGS_remove_redundancy) ? "true" : "false");
  VLOG(1) << boost::format("Distance Prediction: %|30t|%1%") %
                   (absl::GetFlag(FLAGS_distance_prediction) ? "true"
                                                             : "false");
  VLOG(1) << boost::format("Distance Prediction Span: %|30t|%1%") %
                   absl::GetFlag(FLAGS_proximity_span);
  VLOG(1) << boost::format("Split TTL: %|30t|%1%") %
                   absl::GetFlag(FLAGS_split_ttl);
  VLOG(1) << boost::format("Random Seed: %|30t|%1%") %
                   absl::GetFlag(FLAGS_seed);
  VLOG(1) << boost::format("Scan Count: %|30t|%1%") %
                   absl::GetFlag(FLAGS_scan_count);

  VLOG(1) << " ========== Miscellaneous ========== ";
  VLOG(1) << boost::format("Hitlist: %|30t|%1%") % absl::GetFlag(FLAGS_hitlist);
  VLOG(1) << boost::format("Target: %|30t|%1%") % absl::GetFlag(FLAGS_targets);
  VLOG(1) << boost::format("Output: %|30t|%1%") % absl::GetFlag(FLAGS_output);
}

int main(int argc, char* argv[]) {
  FLAGS_alsologtostderr = 1;

  google::InitGoogleLogging(argv[0]);
  absl::SetProgramUsageMessage("This program does nothing.");
  absl::ParseCommandLine(argc, argv);

  if (absl::GetFlag(FLAGS_vverbose)) {
    FLAGS_v = 2;
  } else if (absl::GetFlag(FLAGS_verbose)) {
    FLAGS_v = 1;
  }

  ProberType proberType = ProberType::UDP_PROBER;
  if (absl::GetFlag(FLAGS_prober_type).compare("udp") == 0) {
    proberType = ProberType::UDP_PROBER;
  } else if (absl::GetFlag(FLAGS_prober_type).compare("udp_idempotent") == 0) {
    proberType = ProberType::UDP_IDEMPOTENT_PROBER;
  } else {
    LOG(FATAL) << "Unkown prober type.";
  }

  // gflags::ParseCommandLineFlags(&argc, &argv, true);
  // Get propositional parameters.
  std::string target = std::string(argv[argc - 1]);
  std::string defaultInterface = getDefaultInterface();
  if (absl::GetFlag(FLAGS_interface).size() == 0) {
    finalInterface = defaultInterface;
  } else {
    finalInterface = absl::GetFlag(FLAGS_interface);
  }

  bool targetIsNetwork = isNetwork(target);

  printFlags();
  std::signal(SIGINT, signalHandler);
  if (!absl::GetFlag(FLAGS_targets).empty() || targetIsNetwork) {
    commandExecutor = std::make_unique<CommandExecutor>();
    // Launch tcpdump to collect data.
    if (!absl::GetFlag(FLAGS_tcpdump_output).empty()) {
      std::string tcpdumpCommandline = absl::StrCat(
          "tcpdump icmp and inbound -w ", absl::GetFlag(FLAGS_tcpdump_output));
      commandExecutor->run(tcpdumpCommandline);
    }

    std::time_t now = std::time(0);
    uint32_t seed = absl::GetFlag(FLAGS_seed);
    if (seed == 0) seed = static_cast<std::uint32_t>(now);

    // Remove exclusion/blacklist list.
    Blacklist blacklist;

    blacklist.loadRulesFromFile(absl::GetFlag(FLAGS_blacklist));

    // Remove reserved addresses.
    if (absl::GetFlag(FLAGS_remove_reserved_addresses)) {
      blacklist.loadRulesFromReservedAddress();
      LOG(INFO) << "Load " << blacklist.size() << " blacklist rules.";
    }

    BogonFilter bogonFilter{absl::GetFlag(FLAGS_bogon_filter_potaroo)};

    Targets targetLoader(absl::GetFlag(FLAGS_split_ttl), seed, &blacklist,
                         &bogonFilter);

    ResultDumper* resultDumper = nullptr;
    if (!absl::GetFlag(FLAGS_output).empty()) {
      resultDumper = new ResultDumper(absl::GetFlag(FLAGS_output));
    }

    DcbManager* dcbManager;
    // Load targets.
    if (!absl::GetFlag(FLAGS_targets).empty()) {
      dcbManager = targetLoader.loadTargetsFromFile(
          absl::GetFlag(FLAGS_targets),
          static_cast<uint8_t>(absl::GetFlag(FLAGS_distance_prediction_prefix)),
          absl::GetFlag(FLAGS_distance_prediction));
    } else {
      dcbManager = targetLoader.generateTargetsFromNetwork(
          target, static_cast<uint8_t>(absl::GetFlag(FLAGS_granularity)),
          absl::GetFlag(FLAGS_distance_prediction));
    }

    // Learn route length from the history
    if (!absl::GetFlag(FLAGS_history_probing_result).empty()) {
      LOG(INFO) << "Update split TTL based on the history scan.";
      updateDcbsBasedOnHistory(absl::GetFlag(FLAGS_history_probing_result),
                               dcbManager);
    }

    // check if the scan is for ipv4 or ipv6.
    bool ipv4 = true;
    if (dcbManager->peek() != nullptr) {
      ipv4 = dcbManager->peek()->ipAddress->isIpv4();
    }

    NetworkManager networkManager(NULL, finalInterface,
                                  absl::GetFlag(FLAGS_probing_rate), ipv4);

    Tracerouter traceRouter(
        dcbManager, &networkManager, resultDumper,
        absl::GetFlag(FLAGS_split_ttl), absl::GetFlag(FLAGS_preprobing_ttl),
        absl::GetFlag(FLAGS_forward_probing), absl::GetFlag(FLAGS_gaplimit),
        absl::GetFlag(FLAGS_remove_redundancy), absl::GetFlag(FLAGS_preprobing),
        absl::GetFlag(FLAGS_distance_prediction),
        absl::GetFlag(FLAGS_proximity_span), absl::GetFlag(FLAGS_scan_count),
        absl::GetFlag(FLAGS_src_port), absl::GetFlag(FLAGS_dst_port),
        absl::GetFlag(FLAGS_default_payload_message),
        absl::GetFlag(FLAGS_encode_timestamp), absl::GetFlag(FLAGS_ttl_offset));
    traceRouterPtr = &traceRouter;

    // Load hitlist.
    if (!absl::GetFlag(FLAGS_hitlist).empty()) {
      Hitlist::loadHitlist(absl::GetFlag(FLAGS_hitlist), &traceRouter);
    }

    // Sequential or random sequence of scan.
    if (!absl::GetFlag(FLAGS_sequential_scan)) {
      dcbManager->shuffleOrder();
    }

    // Dump targets to a file.
    if (!absl::GetFlag(FLAGS_dump_targets_file).empty()) {
      // traceRouter.dumpAllTargetsToFile(absl::GetFlag(FLAGS_dump_targets_file));
      return 0;
    }

    traceRouter.startScan(proberType, ipv4, false);

    // Terminate Tcpdump.
    if (!absl::GetFlag(FLAGS_tcpdump_output).empty()) {
      commandExecutor->stop();
    }

    if (resultDumper != nullptr) delete resultDumper;
    if (dcbManager != nullptr) delete dcbManager;

    printFlags();
  } else {
    SingleHost tracerouter(0, absl::GetFlag(FLAGS_dst_port),
                           absl::GetFlag(FLAGS_ttl_offset));
    tracerouter.startScan(target, finalInterface);
  }
  LOG(INFO) << "The program ends.";
}
