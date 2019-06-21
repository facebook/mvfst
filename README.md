
![alt text](logo.png "MVFST")

[![Build Status](https://api.travis-ci.com/facebookincubator/mvfst.svg?branch=master)](https://travis-ci.com/facebookincubator/mvfst)

## Introduction
`mvfst` (Pronounced *move fast*) is a client and server implementation of [IETF QUIC](https://tools.ietf.org/html/draft-ietf-quic-transport-20) protocol in C++ by Facebook. QUIC is a UDP based reliable, multiplexed transport protocol that will become an internet standard. The goal of `mvfst` is to build a performant implementation of the QUIC transport protocol that applications could adapt for use cases on both the internet and the data-center. `mvfst` has been tested at scale on android, iOS apps, as well as servers and has several features to support large scale deployments.

## Features
**Server features**:
- Multi-threaded UDP socket server with a thread local architecture to be able to scale to multi-core servers
- Customizable Connection-Id routing. The default Connection-Id routing implementation integrates seamlessly with [katran](https://github.com/facebookincubator/katran)
- APIs to enable zero-downtime restarts of servers, so that applications do not have to drop connections when restarting.
- APIs to expose transport and server statistics for debuggability
- Zero-Rtt connection establishment and customizable zero rtt path validation
- Support for UDP Generic segmentation offloading (GSO) for faster UDP writes.

**Client features**:
- Native happy eyeballs support between ipv4 and ipv6 so that applications do not need to implement it themselves
- Pluggable congestion control and support for turning off congestion control to plug in application specific control algorithms
- QUIC trace APIs to retrieve deep transport level stats.

## Source Layout
- `quic/api`:         Defines API that applications can use to interact with the QUIC transport layer.
- `quic/client`:      Client transport implementation
- `quic/codec`:       Read and write codec implementation for the protocol
- `quic/common`:      Implementation of common utility functions
- `quic/congestion_control`: Implementation of different congestion control algorithms such as Cubic and Copa
- `quic/flowcontrol`: Implementations of flow control functions
- `quic/handshake`:   Implementations cryptographic handshake layer
- `quic/happyeyeballs`: Implementation of mechanism to race IPV4 and IPV6 connection and pick a winner
- `quic/logging`:     Implementation of logging framework
- `quic/loss`:        Implementations of different loss recovery algorithms
- `quic/samples`:     Example client and server
- `quic/server`:      Server transport implementation
- `quic/state`:       Defines and implements both connection and stream level state artifacts and state machines


## Dependencies

`mvfst` largely depends on two libraries: [folly](https://www.github.com/facebook/folly) and [fizz](https://www.github.com/facebookincubator/fizz).

## Building mvfst

### Ubuntu 16+

To begin, you should install the dependencies we need for build. This largely
consists of dependencies from [folly](https://github.com/facebook/folly) as well as
[fizz](https://github.com/facebookincubator/fizz).

```
sudo apt-get install         \
    g++                      \
    cmake                    \
    libboost-all-dev         \
    libevent-dev             \
    libdouble-conversion-dev \
    libgoogle-glog-dev       \
    libgflags-dev            \
    libiberty-dev            \
    liblz4-dev               \
    liblzma-dev              \
    libsnappy-dev            \
    make                     \
    zlib1g-dev               \
    binutils-dev             \
    libjemalloc-dev          \
    libssl-dev               \
    pkg-config               \
    libsodium-dev
```

Then, build and install folly and fizz

Alternatively, run the helper script `build_helper.sh` in this subdirectory.
It will install and link the required dependencies and also build folly and fizz.
This may take several minutes the first time.

```
./build_helper.sh
```

After building, the directory `_build/` will contain the dependencies
(under `_build/deps`) whereas `_build/build` will contain all the
built libraries and binaries for `mvfst`.

You can also install `mvfst` as well as its dependencies `folly` and `fizz`
to a custom directory using the build script, by supplying an `INSTALL_PREFIX`
env var.
```
./build_helper.sh -i /usr/local
```
See `./build_helper.sh --help` for more options

You might need to run the script as root to install to certain directories.

By default the build script `build_helper.sh` enables the building of test target (i.e. runs with `-DBUILD_TEST=ON` option). Since some of tests in `mvfst` require some test artifacts of Fizz, it is necessary to supply the path of the Fizz src directory (via option `DFIZZ_PROJECT`) to correctly build all test targets in `mvfst`.

## Run a sample client and server
Building the test targets of `mvfst` (or via `build_helper.sh`) should automatically build the sample client and server binaries into the default `_build/build` directory (or whichever target directory was specified). The server will automatically bind to `::1` by default if no host is used, but you can then spin a simple echo server by running:
```
./_build/build/quic/samples/echo -mode=server -host=<host> -port=<port>
```
and to run a client:
```
./_build/build/quic/samples/echo -mode=client -host=<host> -port=<port>
```
For more options, see
```
./_build/build/quic/samples/echo --help
```
## Contributing

We'd love to have your help in making `mvfst` better. If you're interested, please
read our guide to [guide to contributing](CONTRIBUTING.md)

Please also join our
[slack](https://join.slack.com/t/mvfst/shared_invite/enQtNjE0ODIwNDU3MDU4LWFkOTc0ZTQ4NzczZmE2MjRlMjQxNWQxNDAyYzAzMDQ5MTQ0ZGI0YTJhZWM0MThhM2FiYzc0Zjg3MTYyNDg2MWI) to ask questions or start discussions.

## License
`mvfst` is MIT licensed, as found in the LICENSE file.

## API
The API should be considered in alpha. We can't predict all the use cases that
people will have, so we're waiting some time before declaring a more stable API.
We are open to have several different APIs for different constraints.

## Reporting and Fixing Security Issues

Please do not open GitHub issues or pull requests - this makes the problem
immediately visible to everyone, including malicious actors. Security issues in
`mvfst` can be safely reported via Facebook's Whitehat Bug Bounty program:

https://www.facebook.com/whitehat

Facebook's security team will triage your report and determine whether or not is
it eligible for a bounty under our program.
