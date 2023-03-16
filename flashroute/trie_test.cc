/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "flashroute/trie.h"
#include "flashroute/utils.h"

using namespace flashroute;

TEST(Trie, CheckPrefixLength24Contained) {
  // Ipv4 Trie
  TrieManager trie{true};
  auto addr1 = std::unique_ptr<IpAddress>(
      parseIpFromStringToIpAddress("123.123.123.123"));

  auto addr2 = std::unique_ptr<IpAddress>(
      parseIpFromStringToIpAddress("123.123.123.124"));

  auto addr3 = std::unique_ptr<IpAddress>(
      parseIpFromStringToIpAddress("123.123.123.0"));

  auto addr4 = std::unique_ptr<IpAddress>(
      parseIpFromStringToIpAddress("123.123.123.255"));
  trie.insert(*addr1, 24);

  EXPECT_EQ(trie.checkAddressContained(*addr1), true);

  EXPECT_EQ(trie.checkAddressContained(*addr2), true);

  EXPECT_EQ(trie.checkAddressContained(*addr3), true);

  EXPECT_EQ(trie.checkAddressContained(*addr4), true);
}

TEST(Trie, CheckPrefixLength1Contained) {
  // Ipv4 Trie
  TrieManager trie{true};
  auto addr1 = std::unique_ptr<IpAddress>(
      parseIpFromStringToIpAddress("123.123.123.123"));

  auto addr2 = std::unique_ptr<IpAddress>(
      parseIpFromStringToIpAddress("0.0.0.0"));

  auto addr3 = std::unique_ptr<IpAddress>(
      parseIpFromStringToIpAddress("255.255.255.255"));

  auto addr4 = std::unique_ptr<IpAddress>(
      parseIpFromStringToIpAddress("127.255.255.255"));

  auto addr5 = std::unique_ptr<IpAddress>(
      parseIpFromStringToIpAddress("128.0.0.1"));
  trie.insert(*addr1, 1);

  EXPECT_EQ(trie.checkAddressContained(*addr1), true);

  EXPECT_EQ(trie.checkAddressContained(*addr2), true);

  EXPECT_EQ(trie.checkAddressContained(*addr3), false);

  EXPECT_EQ(trie.checkAddressContained(*addr4), true);

  EXPECT_EQ(trie.checkAddressContained(*addr5), false);
}