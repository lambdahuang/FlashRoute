/* Copyright (C) 2019 Neo Huang - All Rights Reserved */

#include <cmath>
#include <memory>

#include "flashroute/address.h"


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

  uint64_t Ipv4Address::getIpv6AddressPrefix() const {
    return 0;
  }

  uint64_t Ipv4Address::getIpv6AddressSuffix() const {
    return 0;
  }

  uint64_t Ipv4Address::getPrefix(uint8_t length) const {
    return address_ >> (32-length);
  }

  void Ipv4Address::randomizeAddress(uint8_t length) {
    uint32_t blockFactor_ = static_cast<uint32_t>(std::pow(2, 32 - length));
    address_ =
        (address_ >> (32 - length)) << (32 - length) | (rand() % blockFactor_);
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
     addressPrefix_ = 0;
     addressSuffix_ = 0;
  }

  Ipv6Address::Ipv6Address(uint64_t prefix, uint64_t suffix) {
     addressPrefix_ = prefix;
     addressSuffix_ = suffix;
  }


  Ipv6Address::Ipv6Address(const Ipv6Address& copy) {
    addressPrefix_ = copy.addressPrefix_;
    addressSuffix_ = copy.addressSuffix_;
  }

  Ipv6Address* Ipv6Address::clone() const { return new Ipv6Address(*this); }

  uint32_t Ipv6Address::getIpv4Address() const {
    return 0;
  }

  uint64_t Ipv6Address::getIpv6AddressPrefix() const {
    return addressPrefix_;
  }

  uint64_t Ipv6Address::getIpv6AddressSuffix() const {
    return addressSuffix_;
  }

  uint64_t Ipv6Address::getPrefix(uint8_t length) const {
    if (length < 64) {
      return addressPrefix_ >> (64-length);
    } else {
      return 0;
    }
  }

  void Ipv6Address::randomizeAddress(uint8_t length) {
    if (length >= 64) {
      uint64_t blockFactor_ = static_cast<uint64_t>(std::pow(2, 128 - length));
      addressSuffix_ = (addressSuffix_ >> (128 - length)) << (128 - length) |
                       (rand() % blockFactor_);
    } else {
      addressSuffix_ = (rand() % static_cast<uint64_t>(std::pow(2, 64)));
      addressPrefix_ =
          (addressSuffix_ >> (64 - length)) << (64 - length) |
          (rand() % static_cast<uint64_t>(std::pow(2, (64 - length))));
    }
  }

  bool Ipv6Address::equal_to(const IpAddress& rhs) const {
    Ipv6Address& temp = dynamic_cast<Ipv6Address&>(const_cast<IpAddress&>(rhs));
    return addressPrefix_ == temp.addressPrefix_ &&
           addressSuffix_ == temp.addressSuffix_;
  }

  bool Ipv6Address::compare_to(const IpAddress& rhs) const {
    if (addressPrefix_ > rhs.getIpv6AddressPrefix())
      return true;
    else if (addressPrefix_ == rhs.getIpv6AddressPrefix() &&
             addressSuffix_ > rhs.getIpv6AddressSuffix())
      return true;
    else
      return false;
  }

  IpAddress& Ipv6Address::set_to(const IpAddress& rhs) {
    this->addressPrefix_ = rhs.getIpv6AddressPrefix();
    this->addressSuffix_ = rhs.getIpv6AddressSuffix();
    return *this;
  }

  bool Ipv6Address::isIpv4() const {
    return false;
  }

  uint64_t Ipv6Address::hash() const {
    return (addressPrefix_ ^ addressSuffix_) % __SIZE_MAX__;
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
      if (prefix_ <= 64) {
        if ((addr_->getIpv6AddressPrefix() >> (64 - prefix_)) ==
            (addr.getIpv6AddressPrefix() >> (64 - prefix_)))
          return true;
        else
          return false;
      } else {
        if (addr_->getIpv6AddressPrefix() == addr.getIpv6AddressPrefix()) {
          if ((addr_->getIpv6AddressSuffix() >> (128 - prefix_)) ==
              (addr.getIpv6AddressSuffix() >> (128 - prefix_)))
            return true;
          else
            return false;
        } else {
          return false;
        }
      }
    }
  }

  IpNetwork* IpNetwork::clone() const {
    return new  IpNetwork(*this);
  }

}  // namespace flashroute
