/* Copyright (C) 2019 Neo Huang - All Rights Reserved */

#include <cmath>
#include <memory>

#include "flashroute/address.h"
#include "absl/random/random.h"


namespace flashroute {
  Ipv4Address::Ipv4Address() {
    address_ = 0;
  }

  Ipv4Address::Ipv4Address(uint32_t ipv4) {
    address_ = ipv4;
  }

  Ipv4Address::Ipv4Address(const Ipv4Address& copy) {
    address_ = copy.address_;
  }

  Ipv4Address* Ipv4Address::clone() const { return new Ipv4Address(*this); }

  uint32_t Ipv4Address::getIpv4Address() const {
    return address_;
  }

  absl::uint128 Ipv4Address::getIpv6Address() const {
    return 0;
  }

  absl::uint128 Ipv4Address::getPrefix(uint8_t length) const {
    return address_ >> (32-length);
  }

  void Ipv4Address::randomizeAddress(uint8_t length) {
    uint32_t blockFactor = static_cast<uint32_t>(std::pow(2, 32 - length));
    absl::BitGen bitgen;
    address_ = (address_ >> (32 - length)) << (32 - length) |
               absl::uniform_int_distribution<uint32_t>(0, blockFactor)(bitgen);
  }

  bool Ipv4Address::equal_to(const IpAddress& rhs) const {
    return address_ ==
           dynamic_cast<Ipv4Address&>(const_cast<IpAddress&>(rhs)).address_;
  }

  bool Ipv4Address::compare_to(const IpAddress& rhs) const {
    return address_ > rhs.getIpv4Address();
  }

  IpAddress& Ipv4Address::set_to(const IpAddress& rhs) {
    this->address_ = rhs.getIpv4Address();
    return *this;
  }

  bool Ipv4Address::isIpv4() const {
    return true;
  }

  size_t Ipv4Address::hash() const { return (address_) % __SIZE_MAX__; }

  // Ipv6 implementation

  Ipv6Address::Ipv6Address() {
     address_ = 0;
  }

  Ipv6Address::Ipv6Address(absl::uint128 address) {
     address_ = address;
  }


  Ipv6Address::Ipv6Address(const Ipv6Address& copy) {
     address_ = copy.address_;
  }

  Ipv6Address* Ipv6Address::clone() const { return new Ipv6Address(*this); }

  uint32_t Ipv6Address::getIpv4Address() const {
    return 0;
  }

  absl::uint128 Ipv6Address::getIpv6Address() const {
    return address_;
  }

  absl::uint128 Ipv6Address::getPrefix(uint8_t length) const {
    return address_ >> (128 - length);
  }

  void Ipv6Address::randomizeAddress(uint8_t length) {
    absl::BitGen bitgen;
    if (length >= 64) {
      uint64_t blockFactor_ = static_cast<uint64_t>(std::pow(2, 128 - length));
      uint64_t addressSuffix_ =
          (absl::Uint128Low64(address_) >> (128 - length)) << (128 - length) |
          absl::uniform_int_distribution<uint64_t>(0, blockFactor_-1)(bitgen);
      address_ = ((address_ >> (128 - length)) << (128 - length)) |
                 static_cast<absl::uint128>(addressSuffix_);
    } else {
      uint64_t blockFactor_ = static_cast<uint64_t>(std::pow(2, 64 - length));
      uint64_t addressSuffix_ = absl::uniform_int_distribution<uint64_t>(
          0, static_cast<uint64_t>(std::pow(2, 64) - 1))(bitgen);
      uint64_t addressPrefix_ =
          (absl::Uint128High64(address_) >> (64 - length)) << (64 - length) |
          absl::uniform_int_distribution<uint64_t>(0, blockFactor_ - 1)(bitgen);

      address_ = static_cast<absl::uint128>(addressPrefix_) |
                 static_cast<absl::uint128>(addressSuffix_);
    }
  }

  bool Ipv6Address::equal_to(const IpAddress& rhs) const {
    Ipv6Address& temp = dynamic_cast<Ipv6Address&>(const_cast<IpAddress&>(rhs));
    return address_ == temp.address_;
  }

  bool Ipv6Address::compare_to(const IpAddress& rhs) const {
    return address_ > rhs.getIpv6Address();
  }

  IpAddress& Ipv6Address::set_to(const IpAddress& rhs) {
    this->address_ = rhs.getIpv6Address();
    return *this;
  }

  bool Ipv6Address::isIpv4() const {
    return false;
  }

  uint64_t Ipv6Address::hash() const {
    return (absl::Uint128High64(address_) ^ absl::Uint128Low64(address_)) %
           __SIZE_MAX__;
  }

  // Ipv network implementation

  IpNetwork::IpNetwork(const IpAddress& addr, const uint32_t prefix) {
    addr_ = std::unique_ptr<IpAddress>(addr.clone());
    prefix_ = prefix;
  }

  IpNetwork::IpNetwork(const IpNetwork& copy) {
    this->addr_.reset(copy.addr_->clone());
    this->prefix_ = copy.prefix_;
  }

  bool IpNetwork::contains(const IpAddress& addr) const {
    if (addr.isIpv4()) {
      if ((addr_->getIpv4Address() >> (32 - prefix_)) ==
          (addr.getIpv4Address() >> (32 - prefix_)))
        return true;
      else
        return false;
    } else {
      if ((addr_->getIpv6Address() >> (128 - prefix_)) ==
          (addr.getIpv6Address() >> (128 - prefix_)))
        return true;
      else
        return false;
    }
  }

  IpNetwork* IpNetwork::clone() const {
    return new  IpNetwork(*this);
  }

}  // namespace flashroute
