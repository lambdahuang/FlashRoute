/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#pragma once

#include "glog/logging.h"

void logIpAddress(uint32_t ip) {
  uint32_t section[4];
  section[0] = ip & 0xFF;
  section[1] = (ip >> 8) & 0xFF;
  section[2] = (ip >> 16) & 0xFF;
  section[3] = (ip >> 24) & 0xFF;
  LOG(INFO) << section[3] << "." << section[2] << "." << section[1] << "."
            << section[0];
}
