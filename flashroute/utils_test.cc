/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#include "gtest/gtest.h"

#include "flashroute/utils.h"

using namespace flashroute;

TEST(getFirstAddressOfBlock, RegularNumberTeset) {
  // 192.168.1.223 -> 192.168.1.0
  EXPECT_EQ(getFirstAddressOfBlock(3232235999, 24), 3232235776);
  EXPECT_EQ(getFirstAddressOfBlock(3232235993, 24), 3232235776);
  EXPECT_EQ(getFirstAddressOfBlock(3232235993, 16), 3232235520);
  EXPECT_EQ(getFirstAddressOfBlock(3232235993, 8), 3221225472);
  EXPECT_EQ(getFirstAddressOfBlock(3232235993, 0), 0);
}

TEST(getLastAddressOfBlock, RegularNumberTeset) {
  EXPECT_EQ(getLastAddressOfBlock(3232235999, 24), 3232236031);
  EXPECT_EQ(getLastAddressOfBlock(3232235788, 24), 3232236031);
  EXPECT_EQ(getLastAddressOfBlock(3232235993, 16), 3232301055);
  EXPECT_EQ(getLastAddressOfBlock(3232235993, 8), 3238002687);
  EXPECT_EQ(getLastAddressOfBlock(3232235993, 0), 4294967295);
}

TEST(parseIpFromStringToInt, convertStringToDecimal) {
  EXPECT_EQ(parseIpFromStringToInt("192.168.1.255"), 3232236031);
  EXPECT_EQ(parseIpFromStringToInt("255.255.255.255"), 4294967295);
}