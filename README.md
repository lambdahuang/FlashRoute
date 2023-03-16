# FlashRoute6 (IPv6 Compatible)

[![Build Status](https://travis-ci.com/lambdahuang/FlashRoute.svg?branch=v0.1.0)](https://travis-ci.com/lambdahuang/FlashRoute)
[![Generic badge](https://img.shields.io/badge/c\++-14-blue.svg)](https://shields.io/)
[![Generic badge](https://img.shields.io/badge/bazel-3.7.2-blue.svg)](https://shields.io/)

FlashRoute is now supporting **IPv6 scan and customized target list** starting from v0.1.0!

Considering changes in the internal design, the users may find the old FlashRoute from branch v0.0.2.

Also for users who are directed from "https://osf.io/kw5jr/" (FlashRoute), you probably also look for branch v0.0.2.

For users who are directed from  "https://osf.io/8xv5r/ (FlashRoute6), the default branch is what you look for.

___

![Gif](https://github.com/lambdahuang/FlashRoute/blob/v0.0.2/example.gif)

FlashRoute is a tool to discover network topology, which is specially optimized for full Internet topology discovery. 
It has high time efficiency in which it can finish the scan over the full IPv4 /24 address space in 7 minutes at probing speed of 200 Kpps, and 17 mins at probing speed of 100 Kpps.
It also has high network efficiency, in which it can finishes the scan using only 75% of probes used by Scamper [4] and 30% of probes used by Yarrp [2] to finish the same task.

To have such efficiency, FlashRoute utilizes the ideas from previous accomplishments [1-3] and combines with some novel ideas.
FlashRoute has almost all merits of previous state-of-arts but avoids their short boards.
To sum up, FlashRoute has following features:

* FlashRoute can scan in a high parallism.

* FlashRoute can greatly reduce the intrusiveness to the Internet.

* FlashRoute can avoid overprobing the neighborhood routers.

* FlashRoute can discover more router interfaces using the same amount of time of other alternatives (discovery-optimized mode).

FlashRoute may help you if

* You are a researcher and want to study the dynamicity of topology of Internet. 

* You are a network operator and need to investigate the connectivity issues from a single point to a large number of destiantions. 

* You are enthusiast and want to play with massive tracerouting but don't want to be aggressive to the Internet.  

## References

[1] Donnet, B., Curie, M., Raoult, P., Curie, M., Cnrs, L. L., Curie, M., & Crovella, M. (2005). Efficient Algorithms for Large-Scale Topology Discovery. 327–338.

[2] Beverly, R. (2016). Yarrp’ing the Internet. 413–420. https://doi.org/10.1145/2987443.2987479

[3] Durumeric, Zakir, Eric Wustrow, and J. Alex Halderman. "ZMap: Fast Internet-wide scanning and its security applications." Presented as part of the 22nd {USENIX} Security Symposium ({USENIX} Security 13). 2013.

[4] Luckie, M. (2010). Scamper. 239. https://doi.org/10.1145/1879141.1879171


# Installation

FlashRoute is developed using C++ 14 along with a number of third-party libraries, including [ Boost ](https://www.boost.org/), [ Abseil ](https://abseil.io/), [ GFlag ](https://gflags.github.io/gflags/), and [ GLog ](https://github.com/google/glog) C++ libraries.
The build of FlashRoute relies on [Bazel](https://bazel.build/) open source project, which can greatly improve the user experience when multiple people contributes to the same project.

Thanks to Bazel, users do not need to manually install most of aforementioned libraries/components,
but Bazel can automatically help you download the correct version of libraries and compile them with the source of FlashRoute.
Some libraries may need a system-wide installation to support their functionalities.
In this section, we will provide some preparation steps for compiling the project. Trust me, they are all simple.

### 1. GFlags

GFlags is an open-source project from Google, which supports flags parsing functionalities.

On Ubuntu, we can directly install it by running this commandline:

```
sudo apt-get install libgflags-dev
```

### 2. GLog

Similar to GFlags, GLog is also an Google's open source project to provide logging functionalities.

```
sudo apt install libgoogle-glog-dev
```

### 3. Bazel

Bazel is an open-source build system, developed by Google and widely adopted by other companies.

Bazel supports [ different installation methods ](https://docs.bazel.build/versions/master/install-ubuntu.html).

This example provides the installation of Bazel 3.7.2, but you can freely replace the version to whatever the version you like to install.
FlashRoute can be built by Bazel from 0.x to 3.7 on x86_64 machines.
However, for Arm users, **Bazel 2.1.1 is recommended**.

```
wget https://github.com/bazelbuild/bazel/releases/download/3.7.2/bazel-3.7.2-installer-linux-x86_64.sh

chmod +x bazel-3.7.2-installer-linux-x86_64.sh
./bazel-3.7.2-installer-linux-x86_64.sh --user
export PATH="$PATH:$HOME/bin"
export BAZEL_CXXOPTS="-std=c++14" 
```

### Other Compiling Requirements

**Linux Kernel 4.18+** is required to build the IPv6 compatibility.
**gcc 5++** is required.

# Compiling

**Caveat**: Make sure your computer has Internet connection when building, Bazel will download underlying libraries for FlashRoute.

The compiling can be done simply using this commandline inside the directory of this project.

```
bazel build flashroute
```

On some systems, the default version of C++ is not set to 14, in this case, you may specify it in `--cxxopt`.

```
bazel build --cxxopt="--std=c++14" flashroute
```

On ARM system, such as Raspberry Pi, you may need add one more linking option `--linkopt`;

```
bazel build --cxxopt="--std=c++14" —linkopt="-latomic" flashroute
```

To optimize the program in the compiling process, you may use this. This can improve program running performance **significantly**.

```
bazel build --cxxopt="--std=c++14" --compilation_mode=opt flashroute
```

# Miscellaneous

FlashRoute uses Clang-format as the linter to check the code-style, which can be installed using following commandline.
However, this is not necessary to compile the project.

### Clang-format

We use clang-format to regulate our code style. To install clang-format:

```
sudo apt-get install clang-format
```

# Usage

FlashRoute supports

## Examples

1. Probe an IPv4 address.

```
sudo ./bazel-bin/flashroute/flashroute --interface eth0 192.168.1.1
```

2. Probe an IPv6 address.

```
sudo ./bazel-bin/flashroute/flashroute --interface eth0 2607:f8b0:4009:805::200e
```

3. Probe all IPv4 /24 subnets (one address per /24 prefix).

```
sudo ./bazel-bin/flashroute/flashroute --interface eth0 --probing_rate 10000 --granularity 24 --output ~/test.output 0.0.0.0/0
```

4. Probe all /48 subnets under a give IPv6 prefix (one address per /48 prefix).

```
sudo ./bazel-bin/flashroute/flashroute --interface eth0 --granularity 48 2607:f8b0:4009:805::200e/44
```

5. You may also store all flags/options using a flagfile and reuse it next time

```
sudo ./bazel-bin/flashroute/flashroute --flagfile ./examples/sample_scan.conf  8.8.8.8
```

## Flags

`--split_ttl` Specify initial TTL to start Scan. By default, 16.

`--granularity` Specify the granularity of the scan. For example, if this value is set to 24, FlashRoute will scan one address per /24 prefix. The range of this value is [0, 32] for Ipv4. By default, 24. Caveat: this value will affect the memory footprint and the network probes and time usage of a scan. For Ipv6, the range of this value is [0, 128]. 

`--prober_type` The type of prober. Options: udp, udp_idempotent.

`--preprobing` Enable optimization to use preprobing measure hop distance first. By default, enabled.

`--preprobing_ttl` Specify TTL for preprobing. By default, 32.

`--distance_prediction` Enable distance prediction, which uses measured distances to predict distances to proximity blocks. By default, enabled.

`--distance_prediction_prefix` Specify the prefix length. When the distance of one address from the prefix is measured, the result will be used to predict the distance of other addresses in the same prefix.

`--forward_probing` Enable forward probing. The forawrd probing explores routes in the forward direction and stops if reaching the destination or experiencing N-consecutive silent interfaces, controlled by `--gaplimit`.

`--gaplimit` Specify the number of consecutive silent interfaces to halt the forward probing. By default, 5.

`--remove_redundancy` Enable Doubletree-based redundancy removal in backward probing. By default, enabled.

`--history_probing_result` Optmize the scan based on the history.

---

`--sequential_scan` Specify the scan all destinations in a sequantial way, otherwise, following random sequence.

---

`--dump_targets_file` If set, FlashRoute will dumps all destinations into a file, one destination per line.

---

`--interface` Specify the interface used by probing. By default, eth0.

`--default_payload_message` Specify the payload of each probe. By default, "test".

`--probing_rate` Specify the probes sending rate in the unit of packet per second. By deafult, 40000.

`--dst_port` Specify the destination port for probing.

`--src_port` Specify the source port for probing. Note: this does not promise to be respected since source port field may be encoded probing context.

---

`--remove_reserved_addresses` Remove the IETF-reserved addresses from scanning. By default, true.

`--blacklist` Specify the file path to blacklist. One IP address per a line. By default, empty.

`--tcpdump_dump_filepath` autorun the tcpdump to collect the packets and dump the collected packets to a pcap file.

<!-- `--hitlist` Specify the file path to Hitlist and use IP from hitlist to replace the random selected IP in each /24 subnet. -->

`--targets` Specify the file path to target list.

`--seed` the seed to select destination IP addresses if users ask for auto-generated targets.

# Result Parsing 

We provide a sample app to parse the result. 

```
bazel run parsers/utils/route_generator -- --file /datastorage/test_temp_output/7_25_fast_scan_268
...
I1022 02:25:16.714200 83727 utils.cc:108] 99.9463% finished.
I1022 02:25:16.730381 83727 utils.cc:111] Processing finished.
I1022 02:25:24.619446 83727 route_generator.cc:31] Finished
I1022 02:25:24.640774 83727 route_generator.cc:45] Destination: 74.188.92.117 Distance: 13
I1022 02:25:24.640806 83727 route_generator.cc:47] Find routes:163
I1022 02:25:24.640808 83727 route_generator.cc:50] Route #1/163
I1022 02:25:24.640812 83727 route_generator.cc:51] Acyclic: False
I1022 02:25:24.640815 83727 route_generator.cc:53] Convergence: 5
I1022 02:25:24.640817 83727 route_generator.cc:55] Address:12.122.2.5 Destination:74.188.92.117 Distance:13
I1022 02:25:24.640820 83727 route_generator.cc:55] Address:199.218.20.30 Destination:104.178.100.231 Distance:8
I1022 02:25:24.640823 83727 route_generator.cc:55] Address:199.218.20.33 Destination:32.253.6.93 Distance:7
I1022 02:25:24.640827 83727 route_generator.cc:55] Address:199.218.39.253 Destination:208.90.49.138 Distance:6
I1022 02:25:24.640830 83727 route_generator.cc:55] Address:199.218.20.94 Destination:208.90.49.138 Distance:5
I1022 02:25:24.640832 83727 route_generator.cc:55] Address:199.218.39.198 Destination:208.90.49.138 Distance:4
I1022 02:25:24.640837 83727 route_generator.cc:55] Address:199.18.156.65 Destination:108.104.77.33 Distance:3
I1022 02:25:24.640842 83727 route_generator.cc:55] Address:192.5.109.238 Destination:78.143.9.198 Distance:2
```


## Referencing the FlashRoute

```
@inproceedings{huang2020flashroute,
  title={FlashRoute: Efficient Traceroute on a Massive Scale},
  author={Huang, Yuchen and Rabinovich, Michael and Al-Dalky, Rami},
  booktitle={Proceedings of the ACM Internet Measurement Conference},
  pages={443--455},
  year={2020}
}
```