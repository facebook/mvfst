/* <MIT License>
 Copyright (c) 2013  Marek Majkowski <marek@popcount.org>
 Copyright (c) 2014  Marco Elver

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
 </MIT License>

 Original location:
    https://github.com/melver/cppsiphash/

 Solution inspired by code from:
    Marek Majkowski (https://github.com/majek/csiphash/)
    Samuel Neves (supercop/crypto_auth/siphash24/little)
    djb (supercop/crypto_auth/siphash24/little2)
    Jean-Philippe Aumasson (https://131002.net/siphash/siphash24.c)
*/

#ifndef SIPHASH_HPP_
#define SIPHASH_HPP_

#include <cstdint>
#include <cstddef>

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
	__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  define _le64toh(x) ((std::uint64_t)(x))
#elif defined(_WIN32)
/* Windows is always little endian, unless you're on xbox360
   http://msdn.microsoft.com/en-us/library/b0084kay(v=vs.80).aspx */
#  define _le64toh(x) ((std::uint64_t)(x))
#elif defined(__APPLE__)
#  include <libkern/OSByteOrder.h>
#  define _le64toh(x) OSSwapLittleToHostInt64(x)
#else

/* See: http://sourceforge.net/p/predef/wiki/Endianness/ */
#  if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#    include <sys/endian.h>
#  else
#    include <endian.h>
#  endif
#  if defined(__BYTE_ORDER) && defined(__LITTLE_ENDIAN) && \
	__BYTE_ORDER == __LITTLE_ENDIAN
#    define _le64toh(x) ((std::uint64_t)(x))
#  else
#    define _le64toh(x) le64toh(x)
#  endif

#endif

namespace siphash {

template <std::uint64_t b>
inline std::uint64_t sip_rotate(const std::uint64_t x)
{
	return ((x) << (b)) | ( (x) >> (64 - (b)));
}

template <std::uint64_t s, std::uint64_t t>
inline void sip_half_round(
		std::uint64_t& a,
		std::uint64_t& b,
		std::uint64_t& c,
		std::uint64_t& d)
{
	a += b; c += d;
	b = sip_rotate<s >(b) ^ a;
	d = sip_rotate<t >(d) ^ c;
	a = sip_rotate<32>(a);
}

inline void sip_double_round(
		std::uint64_t& v0,
		std::uint64_t& v1,
		std::uint64_t& v2,
		std::uint64_t& v3)
{
	sip_half_round<13,16>(v0,v1,v2,v3);
	sip_half_round<17,21>(v2,v1,v0,v3);
	sip_half_round<13,16>(v0,v1,v2,v3);
	sip_half_round<17,21>(v2,v1,v0,v3);
}

struct Key {
	union {
		char          k_char[16];
		std::uint64_t k_uint64[2];
	};

	Key(char k0, char k1, char k2, char k3, char k4, char k5, char k6, char k7,
		char k8, char k9, char ka, char kb, char kc, char kd, char ke, char kf)
		: k_char{k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, ka, kb, kc, kd, ke, kf}
	{}

	Key(std::uint64_t k0, std::uint64_t k1)
		: k_uint64{k0, k1}
	{}
};

inline std::uint64_t siphash24(const void *src, std::size_t len, const Key *key)
{
	const std::uint64_t k0 = _le64toh(key->k_uint64[0]);
	const std::uint64_t k1 = _le64toh(key->k_uint64[1]);
	const std::uint64_t *in = static_cast<const std::uint64_t*>(src);

	std::uint64_t b = static_cast<std::uint64_t>(len) << 56;

	std::uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
	std::uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
	std::uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
	std::uint64_t v3 = k1 ^ 0x7465646279746573ULL;

	while (len >= 8) {
		const std::uint64_t mi = _le64toh(*in);
		in += 1; len -= 8;
		v3 ^= mi;
		sip_double_round(v0,v1,v2,v3);
		v0 ^= mi;
	}

	std::uint64_t t = 0;
	std::uint8_t *pt = reinterpret_cast<std::uint8_t *>(&t);
	const std::uint8_t *m = reinterpret_cast<const std::uint8_t *>(in);

	switch (len) {
		case 7: pt[6] = m[6];
		case 6: pt[5] = m[5];
		case 5: pt[4] = m[4];
		case 4:
				*(reinterpret_cast<std::uint32_t*>(pt)) =
					*(reinterpret_cast<const std::uint32_t*>(m));
				break;
		case 3: pt[2] = m[2];
		case 2: pt[1] = m[1];
		case 1: pt[0] = m[0];
	}
	b |= _le64toh(t);

	v3 ^= b;
	sip_double_round(v0,v1,v2,v3);
	v0 ^= b; v2 ^= 0xff;
	sip_double_round(v0,v1,v2,v3);
	sip_double_round(v0,v1,v2,v3);
	return (v0 ^ v1) ^ (v2 ^ v3);
}

template <class T>
inline std::uint64_t siphash24(const T& src, const Key& key)
{
	return siphash24(&src, sizeof(src), &key);
}

} /* namespace siphash */

#endif /* SIPHASH_HPP_ */
