/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#pragma once

#include <string>

#include "flashroute/traceroute.h"

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
  static void removeAddressFromFile(const std::string& filePath,
                                       Tracerouter* tracerouter);

  // Remove the public reserved ip address
  static void removeReservedAddress(Tracerouter* tracerouter);

  // Given an individual ip adress or a subnet address, the function will remove
  // all ip blocks in this range represented by the mask.
  //
  // Example:
  // Remove a range of ip addresses.
  // removeIpRange(traceRouter, "123.123.123.123/24");
  // Remove an individual ip address.
  // removeIpRange(traceRouter, "123.123.123.123");
  static int64_t removeAddressBlock(Tracerouter* tracerouter,
                                   const std::string& ipBlock);

 private:
};

}  // namespace flashroute
