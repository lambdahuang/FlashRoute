/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#pragma once

#include <memory>
#include <string>

#include <boost/asio.hpp>
#include <boost/process.hpp>
#include "absl/strings/string_view.h"

#include "flashroute/address.h"

namespace flashroute {

class CommandExecutor {
 public:
  CommandExecutor();
  void run(const std::string& command);
  void stop();

 private:
  std::unique_ptr<boost::process::child> child_process_;
};

// Translate string IP to integer IP.
uint32_t parseIpFromStringToInt(const std::string& stringIp);

// Translate string IP to IpAddress. (Currently only support Ipv4)
IpAddress* parseIpFromStringToIpAddress(const std::string& stringIp);

// Convert decimal IP to string.
std::string parseIpFromIntToString(const uint32_t ip);

// Get IP address by interface name. Return empty string, if interface does not
// exist.
std::string getAddressByInterface(const std::string& interface);

// Get first address of a IP block.
Ipv4Address getFirstAddressOfBlock(const uint32_t address,
                                 const int32_t prefixLength);

// Get last address of a IP block.
Ipv4Address getLastAddressOfBlock(const uint32_t address,
                                const int32_t prefixLength);

bool isNetwork(const std::string& input);

bool isValidDestiantion(const std::string& input);

std::string getDefaultInterface();

}  // namespace flashroute
