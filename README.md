

## Building

### Ubuntu 16+

To begin, you should install the dependencies we need for build. This largely
consists of dependencies from [folly](https://github.com/facebook/folly) as well as
[fizz](https://github.com/facebookincubator/fizz).

```
sudo apt-get install \
    g++ \
    cmake \
    libboost-all-dev \
    libevent-dev \
    libdouble-conversion-dev \
    libgoogle-glog-dev \
    libgflags-dev \
    libiberty-dev \
    liblz4-dev \
    liblzma-dev \
    libsnappy-dev \
    make \
    zlib1g-dev \
    binutils-dev \
    libjemalloc-dev \
    libssl-dev \
    pkg-config \
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

## Contributing

We'd love to have your help in making MVFST better. If you're interested, please
read our guide to [guide to contributing](CONTRIBUTING.md)

## License
MVFST is MIT licensed, as found in the LICENSE file.

## Reporting and Fixing Security Issues

Please do not open GitHub issues or pull requests - this makes the problem
immediately visible to everyone, including malicious actors. Security issues in
MVFST can be safely reported via Facebook's Whitehat Bug Bounty program:

https://www.facebook.com/whitehat

Facebook's security team will triage your report and determine whether or not is
it eligible for a bounty under our program.
