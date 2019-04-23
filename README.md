

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
