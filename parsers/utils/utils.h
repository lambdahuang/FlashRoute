#include <map>
#include <string>
#include <unordered_set>
#include <vector>

#include "flashroute/address.h"

using flashroute::IpAddress;
using flashroute::Ipv4Address;
using flashroute::IpAddressHash;
using flashroute::IpAddressEquality;

struct RouteNodev4 {
  uint32_t address;

  /* <Destination IP, Sucessor> */
  std::unordered_map<uint32_t, std::shared_ptr<RouteNodev4>> next;
  /* <Destination IP, Predecessor> */
  std::unordered_map<uint32_t, std::shared_ptr<RouteNodev4>> previous;
  /* <Destination IP, Distance> */
  std::unordered_map<uint32_t, uint8_t> distances;
};

enum RouteType {
  Acyclic,
  Regular
};

struct RouteConstructNodev4 {
  uint32_t address;
  uint32_t destination;
  uint8_t distance;
};

struct Routev4 {
  std::vector<RouteConstructNodev4> route;
  RouteType routeType;
  uint8_t convergencePoint; 
};

// <address, corrsponding route node>
using RouteFullMap = std::unordered_map<uint32_t, std::shared_ptr<RouteNodev4>>;

struct DataElement {
  uint32_t destination[4];
  uint32_t responder[4];
  uint16_t sourcePort;
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

// Read dataset to a graph map
void readDataset(
    std::string file, RouteFullMap &addressMap,
    std::unordered_map<uint32_t, std::shared_ptr<RouteNodev4>> &routeMap);

// Find route from a given point backward to the vantage point
bool findRouteBack(uint32_t address, uint32_t dest,
                   std::vector<RouteConstructNodev4> &route,
                   std::vector<Routev4> &routes,
                   std::unordered_set<uint32_t> &visited,
                   RouteFullMap &addressMap, uint8_t convergencePoint);

void readDataset(std::string file, RouteMap &edgeMap,
                 InterfaceSet &interfaceSet);

GenericEdgeSet edgeMapToGenericEdgeSet(RouteMap &edgeMap);

GenericInterfaceSet
interfaceSetToGenericInterfaceSet(InterfaceSet &interfaceSet);

void cleanInterfaceSet(InterfaceSet &interfaceSet);

void cleanEdgeMap(RouteMap &edgeMap);