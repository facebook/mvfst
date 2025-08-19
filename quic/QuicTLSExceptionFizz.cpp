/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/QuicTLSException.h>

#include <fizz/record/Types.h>
#include <quic/QuicConstants.h>

namespace quic {

std::string cryptoErrorToString(TransportErrorCode code) {
  auto codeVal = static_cast<std::underlying_type_t<TransportErrorCode>>(code);
  auto alertDescNum = codeVal -
      static_cast<std::underlying_type_t<TransportErrorCode>>(
                          TransportErrorCode::CRYPTO_ERROR);

  return "Crypto error: " +
      toString(static_cast<fizz::AlertDescription>(alertDescNum));
}

} // namespace quic
