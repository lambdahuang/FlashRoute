#include <string>
#include <unordered_set>

#include "flashroute/address.h"

using flashroute::IpAddress;
using flashroute::Ipv4Address;
using flashroute::IpAddressHash;
using flashroute::IpAddressEquality;

struct RouteNodev4 {
  uint32_t address;

  std::unordered_map<uint32_t, std::shared_ptr<RouteNodev4>> next;
  std::unordered_map<uint32_t, std::shared_ptr<RouteNodev4>> previous;
};

using RouteFullMap = std::unordered_map<uint32_t, std::shared_ptr<RouteNodev4>>;

struct DataElement {
  uint32_t destination[4];
  uint32_t responder[4];
  uint32_t rtt;
  uint8_t distance;
  uint8_t fromDestination;
  uint8_t ipv4;
} __attribute__((packed));;

using RouteMap =
    std::unordered_map<IpAddress * /* Destiantion */,
                       std::shared_ptr<std::unordered_map<
                           int8_t, IpAddress *>> /* <Distance, Responder> */,
                       IpAddressHash, IpAddressEquality>;

// Ipv4 Generic edge and interface set.
using GenericEdgeSet = std::unordered_set<uint64_t>;
using GenericInterfaceSet = std::unordered_set<uint32_t>;

using InterfaceSet = std::unordered_set<IpAddress * /* Interface */,
                                        IpAddressHash, IpAddressEquality>;

std::string getLogFileName(const std::string &directory,
                           const std::string &prefix);

std::string getStartingTime(const std::string &logFile);

void readDataset(std::string file, RouteMap &edgeMap,
                 InterfaceSet &interfaceSet);

GenericEdgeSet edgeMapToGenericEdgeSet(RouteMap &edgeMap);

GenericInterfaceSet
interfaceSetToGenericInterfaceSet(InterfaceSet &interfaceSet);

void cleanInterfaceSet(InterfaceSet &interfaceSet);

void cleanEdgeMap(RouteMap &edgeMap);