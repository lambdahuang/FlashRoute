/* Copyright (C) 2019 Neo Huang - All Rights Reserved */

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

  bool Ipv4Address::equal_to(const IpAddress& rhs) const {
    return address_ ==
           dynamic_cast<Ipv4Address&>(const_cast<IpAddress&>(rhs)).address_;
  }

  bool Ipv4Address::compare_to(const IpAddress& rhs) const {
    Ipv4Address& cast = dynamic_cast<Ipv4Address&>(const_cast<IpAddress&>(rhs));
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

  bool Ipv6Address::equal_to(const IpAddress& rhs) const {
    Ipv6Address& cast = dynamic_cast<Ipv6Address&>(const_cast<IpAddress&>(rhs));
    return addressPrefix_ == cast.addressPrefix_ &&
           addressSuffix_ == cast.addressSuffix_;
  }

  bool Ipv6Address::compare_to(const IpAddress& rhs) const {
    Ipv6Address& cast = dynamic_cast<Ipv6Address&>(const_cast<IpAddress&>(rhs));
    if (addressPrefix_ > cast.addressPrefix_)
      return true;
    else if (addressPrefix_ == cast.addressPrefix_ &&
             addressSuffix_ > cast.getIpv6AddressSuffix())
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


}  // namespace flashroute
