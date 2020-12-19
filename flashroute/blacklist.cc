/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#include "flashroute/blacklist.h"

#include <fstream>
#include <limits>
#include <string>
#include <vector>

#include <boost/format.hpp>
#include "absl/strings/numbers.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "glog/logging.h"

#include "flashroute/address.h"
#include "flashroute/utils.h"

namespace flashroute {

Blacklist::~Blacklist() {
  LOG(INFO) << "Free the blacklist.";
  for (auto it = rules_.begin(); it != rules_.end(); ++it) {
    free(*it);
  }
}

void Blacklist::insert(IpNetwork* network) {
  rules_.push_back(network->clone());
}

bool Blacklist::contains(const IpAddress& addr) {
  for (auto it = rules_.begin(); it != rules_.end(); ++it) {
    if ((*it)->contains(addr)) return true;
  }
  return false;
}

void Blacklist::loadRulesFromFile(const std::string& filePath) {
  if (filePath.empty()) {
    LOG(INFO) << "Blacklist disabled.";
    return;
  }
  LOG(INFO) << "Load blacklist from file: " << filePath;
  std::ifstream in(filePath);
  if (!in) {
    LOG(ERROR) << "Failed to load blacklist.";
  }
  for (std::string line; getline(in, line);) {
    insertByString(line);
  }
  in.close();
}

void Blacklist::loadRulesFromReservedAddress() {
  std::vector<std::string> reservedAddresses = {
      "0.0.0.0/8",      "10.0.0.0/8",     "100.64.0.0/10", "127.0.0.0/8",
      "169.254.0.0/16", "172.16.0.0/12",  "192.0.0.0/24",  "192.0.2.0/24",
      "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
      "203.0.113.0/24", "224.0.0.0/4",    "240.0.0.0/4"};

  for (const auto& reservedBlock : reservedAddresses) {
    insertByString(reservedBlock);
  }
}

size_t Blacklist::size() { return rules_.size(); }

void Blacklist::insertByString(const std::string& sAddr) {
    IpNetwork* parsedNetwork = parseNetworkFromStringToNetworkAddress(sAddr);
    if (parsedNetwork != NULL) {
      insert(parsedNetwork);
      free(parsedNetwork);
    }
}

}  // namespace flashroute
