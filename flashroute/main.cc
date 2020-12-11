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
#include "flashroute/network.h"
#include "flashroute/traceroute.h"
#include "flashroute/utils.h"
#include "flashroute/hitlist.h"
#include "flashroute/targets.h"
#include "flashroute/udp_prober.h"


ABSL_FLAG(bool, recommended_mode, false,
          "Use recommended configuration.");

ABSL_FLAG(bool, sequential_scan, false, "Sequentially scan all targets.");

ABSL_FLAG(std::string, dump_targets_file, "", "Dump targets to file.");

ABSL_FLAG(std::string, prober_type, "udp",
          "The prober used for the scan. Options: udp, udp idempotent");

ABSL_FLAG(int16_t, split_ttl, 16, "Default split ttl.");
ABSL_FLAG(
    int16_t, granularity, 24,
    "The granularity of scan; that is, scan pick 1 address per the given "
    "length of prefix. The range of this value is [1, 32]. By default, 24.");

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
ABSL_FLAG(int32_t, proximity_span, 5,
          "Proximity span for distnace prediction.");

// Optimization: Forward probing.
ABSL_FLAG(bool, forward_probing, true, "Forward probing to augment scan.");
ABSL_FLAG(int16_t, gaplimit, 5,
          "Max number of consecutive silent hops allowed in forward probing.");

// Optimization: Backward probing.
ABSL_FLAG(bool, remove_redundancy, true,
          "Remove redundancy in backward probing.");

// Miscellaneous
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

std::unique_ptr<Tracerouter> traceRouterPtr;
std::unique_ptr<CommandExecutor> commandExecutor;

std::string finalInterface;

void signalHandler(int signalNumber) {
  LOG(INFO)
      << "Received SIGINT signal. Forcefully terminate program by Ctrl-C.";
  traceRouterPtr.get()->stopScan();
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
}

int main(int argc, char* argv[]) {
  FLAGS_logtostderr = 1;

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

  std::string localIpAddress = getAddressByInterface(finalInterface);
  if (localIpAddress.size() == 0) {
    LOG(INFO) << "Interface does not exist.";
    return 0;
  }

  bool targetIsNetwork = isNetwork(target);

  printFlags();
  std::signal(SIGINT, signalHandler);
  if (targetIsNetwork) {
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

    traceRouterPtr = std::make_unique<Tracerouter>(
        target, absl::GetFlag(FLAGS_split_ttl),
        absl::GetFlag(FLAGS_preprobing_ttl),
        absl::GetFlag(FLAGS_forward_probing), absl::GetFlag(FLAGS_gaplimit),
        absl::GetFlag(FLAGS_remove_redundancy), absl::GetFlag(FLAGS_preprobing),
        absl::GetFlag(FLAGS_distance_prediction),
        absl::GetFlag(FLAGS_proximity_span), absl::GetFlag(FLAGS_scan_count),
        seed, finalInterface, absl::GetFlag(FLAGS_src_port),
        absl::GetFlag(FLAGS_dst_port),
        absl::GetFlag(FLAGS_default_payload_message),
        absl::GetFlag(FLAGS_probing_rate), absl::GetFlag(FLAGS_output),
        absl::GetFlag(FLAGS_encode_timestamp),
        static_cast<uint8_t>(absl::GetFlag(FLAGS_granularity)));

    Tracerouter& traceRouter = *traceRouterPtr.get();

    // Remove exclusion/blacklist list.
    Blacklist::removeAddressFromFile(absl::GetFlag(FLAGS_blacklist),
                                     &traceRouter);

    // Remove reserved addresses.
    if (absl::GetFlag(FLAGS_remove_reserved_addresses))
      Blacklist::removeReservedAddress(&traceRouter);

    // Load hitlist.
    if (!absl::GetFlag(FLAGS_hitlist).empty()) {
      Hitlist::loadHitlist(absl::GetFlag(FLAGS_hitlist), &traceRouter);
    }

    // Load targets.
    Targets::loadTargetsFromFile(absl::GetFlag(FLAGS_targets), &traceRouter);

    // Sequential or random sequence of scan.
    if (!absl::GetFlag(FLAGS_sequential_scan)) {
      traceRouter.shuffleDcbSequence(seed);
    }

    // Dump targets to a file.
    if (!absl::GetFlag(FLAGS_dump_targets_file).empty()) {
      traceRouter.dumpAllTargetsToFile(absl::GetFlag(FLAGS_dump_targets_file));
      return 0;
    }

    traceRouter.startScan(!absl::GetFlag(FLAGS_hitlist).empty(), proberType);

    // Terminate Tcpdump.
    if (!absl::GetFlag(FLAGS_tcpdump_output).empty()) {
      commandExecutor->stop();
    }
    printFlags();
    traceRouterPtr.release();
  } else {
    LOG(INFO) << "Split TTL is " << absl::GetFlag(FLAGS_split_ttl);
    std::unordered_map<uint8_t,
                       std::tuple<std::unique_ptr<IpAddress>, uint32_t>>
        results;
    uint32_t backwardHop = absl::GetFlag(FLAGS_split_ttl);
    bool preprobeUpdated = false;
    uint32_t forwardHorizon = backwardHop;
    uint32_t forwardHop = backwardHop + 1;
    uint32_t destinationHop = 32;
    PacketReceiverCallback response_handler =
        [&results, &destinationHop, &backwardHop, &preprobeUpdated,
         &forwardHorizon, &forwardHop](
            const IpAddress& destination, const IpAddress& responder,
            uint8_t distance, bool fromDestination, uint32_t rtt,
            uint8_t probePhase, uint16_t replyIpid, uint8_t replyTtl,
            uint16_t replySize, uint16_t probeSize, uint16_t probeIpid,
            uint16_t probeSourcePort, uint16_t probeDestinationPort) {
          if (fromDestination) {
            if (!preprobeUpdated) {
              backwardHop = distance;
              forwardHorizon = distance;
              forwardHop = distance + 1;
              LOG(INFO) << "Find destination is "
                        << static_cast<int32_t>(distance) << " hops away.";
              preprobeUpdated = true;
            } else {
              forwardHorizon = 0;
              destinationHop = distance;
              results.insert(
                  {distance,
                   std::make_tuple(
                       std::unique_ptr<IpAddress>(responder.clone()), rtt)});
            }
          } else {
            LOG(INFO) << boost::format("%2% (%1%) rtt: %3% ms") %
                             static_cast<int32_t>(distance) %
                             parseIpFromIntToString(
                                 dynamic_cast<const Ipv4Address&>(responder)
                                     .getIpv4Address()) %
                             rtt;
            results.insert(
                {distance,
                 std::make_tuple(std::unique_ptr<IpAddress>(responder.clone()),
                                 rtt)});
            forwardHorizon = std::max(
                forwardHorizon, static_cast<uint32_t>(
                                    distance + absl::GetFlag(FLAGS_gaplimit)));
            if (forwardHorizon > 32) forwardHorizon = 32;
          }
        };

    UdpProber udpProber(&response_handler, 0, 0, absl::GetFlag(FLAGS_dst_port),
                        absl::GetFlag(FLAGS_default_payload_message),
                        absl::GetFlag(FLAGS_encode_timestamp));
    NetworkManager networkManager(&udpProber, finalInterface, 2);
    auto remoteHost =
        std::unique_ptr<IpAddress>(
          parseIpFromStringToIpAddress(target));
    networkManager.startListening();
    LOG(INFO) << "Preprobe the target and wait 1 seconds...";
    networkManager.schedualProbeRemoteHost(*remoteHost,
                                           absl::GetFlag(FLAGS_preprobing_ttl));
    sleep(1);
    while (backwardHop > 0 || forwardHop <= forwardHorizon) {
      if (backwardHop > 0) {
        LOG(INFO) << boost::format("%1% --> %2% ttl: %3%") % localIpAddress %
                         target % backwardHop;
        networkManager.schedualProbeRemoteHost(*remoteHost, backwardHop);
        backwardHop--;
      }
      if (forwardHop <= forwardHorizon) {
        LOG(INFO) << boost::format("%1% --> %2% ttl: %3%") % localIpAddress %
                         target % (forwardHop);
        networkManager.schedualProbeRemoteHost(*remoteHost, forwardHop);
        forwardHop++;
      }
    }
    LOG(INFO) << "All probes have been sent, wait 5 seconds...";
    // Halt the thread for a second to receive responses.
    sleep(5);

    networkManager.stopListening();
    LOG(INFO) << " ========== Results ==========";
    for (uint8_t i = 1; i <= forwardHop; i++) {
      if (results.find(i) == results.end()) {
        LOG(INFO) << boost::format("%1% %|5t|*") % static_cast<int>(i);
      } else {
        LOG(INFO) << boost::format("%1% %|5t|%2% %|5t|%3% ms") %
                         static_cast<int>(i) %
                         parseIpFromIntToString(
                             (dynamic_cast<const Ipv4Address&>(
                                  *std::get<0>(results.find(i)->second)))
                                 .getIpv4Address()) %
                         std::get<1>(results.find(i)->second);
      }
    }
    LOG(INFO) << " =============================";

    LOG(INFO) << "Checksum Mismatches: " << udpProber.getChecksummismatches();
    LOG(INFO) << "Distance Abnormalities: "
              << udpProber.getDistanceAbnormalities();
  }
  LOG(INFO) << "The program ends.";
}
