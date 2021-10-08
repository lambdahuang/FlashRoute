#include "utils.h"

#include <map>

#include <boost/filesystem.hpp>
#include <boost/range/iterator_range.hpp>

std::string getLogFileName(const std::string &directory,
                           const std::string &prefix) {
  for (const auto &entry : boost::make_iterator_range(
           boost::filesystem::directory_iterator(directory), {})) {
    std::string file = entry.path().string();
    if (prefix != file && file.find(prefix + "_log") != std::string::npos) {
      return file;
    }
  }
  return "";
}

std::string getStartingTime(const std::string &logFile) {

  std::ifstream inFile;
  inFile.open(logFile, std::ios::in);
  std::string line;
  std::getline(inFile, line);
  inFile.clear();
  inFile.seekg(0);
  inFile.close();
  return line.substr(21);
}

std::shared_ptr<RouteNodev4> readDataset(std::string file, RouteFullMap &map) {

  std::ifstream inFile;
  inFile.open(file, std::ios::in | std::ios::binary);
  DataElement buffer;

  uint32_t records = 0;

  std::shared_ptr<RouteNodev4> root;

  std::unordered_map<uint32_t, std::shared_ptr<RouteNodev4>> addressMap;
  // <address, corrsponding route node> 

  std::unordered_map<uint32_t,
                     std::shared_ptr<std::map<uint8_t, uint32_t>>>
      routeRawMap;
  // <destination, <distance, address>>

  while (inFile.peek() != EOF) {
    inFile.read(reinterpret_cast<char *>(&buffer), 39);
    records++;
    if (buffer.ipv4 == 1) {
      // IPv4 address handling.
      auto addr = buffer.responder[0];
      auto dest = buffer.destination[0];
      auto distance = buffer.distance;
      auto destFound = routeRawMap.find(dest);
      if (destFound == routeRawMap.end()) {
        auto tmp = std::make_shared<std::map<uint8_t, uint32_t>>();
        destFound = routeRawMap.insert({dest, tmp}).first;
      }
      destFound->second->insert({distance, addr});
    } else {
      // IPv6 address handling
      // TODO: we need to add the code logic handle IPv6 Address.
    }
  }
  inFile.close();

  for(const auto& elem : routeRawMap) {
    auto dest = elem.first;
    auto& route = elem.second;

    const auto& lowBound = route->cbegin();
    const auto& highBound = route->crbegin();
    uint8_t lowDistance = lowBound->first; 
    uint8_t highDistance = highBound->first; 

    for (uint8_t i =lowDistance; i <= highDistance; i ++  ) {

    }

    for (const auto& node : *route) {
      auto distance = node.first;
      auto addr = node.second;
      auto nodeFound = addressMap.find(addr);
      if (nodeFound == addressMap.end()) {
        auto tmp = std::make_shared<RouteNodev4>(addr);
        nodeFound = addressMap.insert({addr, tmp}).first;
      }
    }
  }
}

void readDataset(std::string file, RouteMap &edgeMap,
                 InterfaceSet &interfaceSet) {

  std::ifstream inFile;
  inFile.open(file, std::ios::in | std::ios::binary);
  DataElement buffer;

  uint32_t records = 0;

  while (inFile.peek() != EOF) {
    inFile.read(reinterpret_cast<char *>(&buffer), 39);
    records++;
    if (buffer.ipv4 == 1) {
      // IPv4 address handling.
      auto addr = new Ipv4Address(buffer.responder[0]);
      if (buffer.fromDestination == true) {
        // Do nothing
      } else if (interfaceSet.find(addr) == interfaceSet.end()) {
        if (buffer.fromDestination == 0) {
          interfaceSet.insert(addr);
        }
      } else {
        delete addr;
      }
      auto dest = new Ipv4Address(buffer.destination[0]);
      if (edgeMap.find(dest) == edgeMap.end()) {
        auto tmp =
            std::make_shared<std::unordered_map<int8_t, IpAddress *>>();
        edgeMap.insert({dest, tmp});
      }
      auto tmp = edgeMap.find(dest)->second;
      if (tmp->find(buffer.distance) == tmp->end()) {
        tmp->insert({buffer.distance, new Ipv4Address(buffer.responder[0])});
      }
    } else {
      // IPv6 address handling
      // TODO: we need to add the code logic handle IPv6 Address.
    }
  }
  inFile.close();
}

GenericInterfaceSet
interfaceSetToGenericInterfaceSet(InterfaceSet &interfaceSet) {
  GenericInterfaceSet genericItSet;
  for (const auto &element : interfaceSet) {
    genericItSet.insert(element->getIpv4Address());
  }
  return genericItSet;
}

GenericEdgeSet edgeMapToGenericEdgeSet(RouteMap &edgeMap) {
  GenericEdgeSet edgeSet;
  for (const auto &key : edgeMap) {
    auto route = key.second;
    uint64_t edge = 0;
    for (const auto &node : *route) {
      if (route->find(node.first - 1) != route->end()) {
        uint64_t current = node.second->getIpv4Address();
        uint64_t previous =
            route->find(node.first - 1)->second->getIpv4Address();
        edge = previous | current >> 32;
        edgeSet.insert(edge);
      }
    }
  }
  return edgeSet;
}

void cleanInterfaceSet(InterfaceSet &interfaceSet) {
  while (!interfaceSet.empty()) {
    auto element = interfaceSet.begin();
    interfaceSet.erase(element);
  }
}

void cleanEdgeMap(RouteMap &edgeMap) {
  while (!edgeMap.empty()) {
    auto element = edgeMap.begin();
    auto keyAddress = element->first;
    auto routeMap = element->second;
    while (!routeMap->empty()) {
      auto pair = routeMap->begin();
      delete pair->second;
      routeMap->erase(pair->first);
    }
    edgeMap.erase(keyAddress);
    delete keyAddress;
  }
}