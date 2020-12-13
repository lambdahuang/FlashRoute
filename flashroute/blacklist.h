/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#pragma once

#include <vector>
#include <string>

#include "flashroute/address.h"

namespace flashroute {

/**
 * Blacklist
 * Load various blacklists and remove corresponding ip-blocks from the probing
 * list.
 *
 * Example:
 * Remove the blacklisted Ipv4 addresses from file:
 * Blacklist::removeAddressFromFile(FLAGS_blacklist, &traceRouter);
 *
 * Remove the reserved Ipv4 addresses per
 * https://en.wikipedia.org/wiki/Reserved_IP_addresses
 * 
 * Blacklist::removeReservedAddress(&traceRouter);
 */

class Blacklist {
 public:
  ~Blacklist();
  void loadRulesFromFile(const std::string& filePath);

  void loadRulesFromReservedAddress();

  void insert(IpNetwork* network);

  bool contains(const IpAddress& addr);

 private:
  std::vector<IpNetwork*> rules_;

  void insertByString(const std::string& addr);
};

}  // namespace flashroute
