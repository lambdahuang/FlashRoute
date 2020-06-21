/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "flashroute/blacklist.h"
#include "flashroute/traceroute.h"

using namespace flashroute;

class MockTracerouter : public Tracerouter {
 public:
  MOCK_METHOD2(getDcbByIpAddress, int64_t(uint32_t address, bool accuracy));
  MOCK_METHOD1(removeDcbElement, int64_t(uint32_t x));
};

TEST(removeAddressBlock, removeAddressTest) {
  MockTracerouter tracerouter;
  EXPECT_CALL(tracerouter, getDcbByIpAddress)
      .WillOnce(testing::Return(110))
      .WillOnce(testing::Return(120));

  EXPECT_CALL(tracerouter, removeDcbElement)
      .Times(11)
      .WillRepeatedly(testing::Return(1));

  std::string target = "192.168.1.1/24";
  EXPECT_EQ(Blacklist::removeAddressBlock(&tracerouter, target), 11);
}

int main(int argc, char** argv) {
  // The following line must be executed to initialize Google Mock
  // (and Google Test) before running the tests.
  ::testing::InitGoogleMock(&argc, argv);
  return RUN_ALL_TESTS();
}
