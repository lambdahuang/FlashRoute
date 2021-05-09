/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#include "gtest/gtest.h"

#include <memory>

#include "flashroute/utils.h"
#include "flashroute/address.h"

using namespace flashroute;

TEST(getFirstAddressOfBlock, RegularNumberTeset) {
  // 192.168.1.223 -> 192.168.1.0
  EXPECT_EQ(std::unique_ptr<IpAddress>(
                getFirstAddressOfBlock(Ipv4Address{3232235999}, 24))
                ->getIpv4Address(),
            3232235776);

  EXPECT_EQ(std::unique_ptr<IpAddress>(
                getFirstAddressOfBlock(Ipv4Address{3232235993}, 24))
                ->getIpv4Address(),
            3232235776);

  EXPECT_EQ(std::unique_ptr<IpAddress>(
                getFirstAddressOfBlock(Ipv4Address{3232235993}, 16))
                ->getIpv4Address(),
            3232235520);

  EXPECT_EQ(std::unique_ptr<IpAddress>(
                getFirstAddressOfBlock(Ipv4Address{3232235993}, 8))
                ->getIpv4Address(),
            3221225472);

  EXPECT_EQ(std::unique_ptr<IpAddress>(
                getFirstAddressOfBlock(Ipv4Address{3232235993}, 0))
                ->getIpv4Address(),
            0);
}

TEST(getLastAddressOfBlock, RegularNumberTeset) {

  EXPECT_EQ(std::unique_ptr<IpAddress>(
                getLastAddressOfBlock(Ipv4Address{3232235999}, 24))
                ->getIpv4Address(),
            3232236031);

  EXPECT_EQ(std::unique_ptr<IpAddress>(
                getLastAddressOfBlock(Ipv4Address{3232235788}, 24))
                ->getIpv4Address(),
            3232236031);

  EXPECT_EQ(std::unique_ptr<IpAddress>(
                getLastAddressOfBlock(Ipv4Address{3232235993}, 16))
                ->getIpv4Address(),
            3232301055);

  EXPECT_EQ(std::unique_ptr<IpAddress>(
                getLastAddressOfBlock(Ipv4Address{3232235993}, 8))
                ->getIpv4Address(),
            3238002687);

  EXPECT_EQ(std::unique_ptr<IpAddress>(
                getLastAddressOfBlock(Ipv4Address{3232235993}, 0))
                ->getIpv4Address(),
            4294967295);
}

TEST(parseIpFromStringToInt, convertStringToDecimal) {
  EXPECT_EQ(parseIpFromStringToInt("192.168.1.255"), 3232236031);
  EXPECT_EQ(parseIpFromStringToInt("255.255.255.255"), 4294967295);
}