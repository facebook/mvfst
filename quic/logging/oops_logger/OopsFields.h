/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

namespace proto_oops {

struct OopsFields {
  std::string component;
  std::string errorMessage;
  std::chrono::system_clock::time_point timestamp;

  std::optional<uint32_t> version;
  std::optional<std::string> alpn;
  std::optional<std::string> connectionId;
  std::optional<uint64_t> streamId;

  std::optional<uint64_t> errorCode;
  std::optional<std::string> exceptionType;

  std::optional<std::string> buildRevision;
};

class OopsFieldsBuilder {
 public:
  OopsFieldsBuilder() = default;

  OopsFieldsBuilder& setComponent(std::string c) {
    component_ = std::move(c);
    return *this;
  }

  OopsFieldsBuilder& setErrorMessage(std::string msg) {
    errorMessage_ = std::move(msg);
    return *this;
  }

  OopsFieldsBuilder& setVersion(uint32_t v) {
    version_ = v;
    return *this;
  }

  OopsFieldsBuilder& setAlpn(std::string a) {
    alpn_ = std::move(a);
    return *this;
  }

  OopsFieldsBuilder& setConnectionId(std::string cid) {
    connectionId_ = std::move(cid);
    return *this;
  }

  OopsFieldsBuilder& setStreamId(uint64_t sid) {
    streamId_ = sid;
    return *this;
  }

  OopsFieldsBuilder& setErrorCode(uint64_t code) {
    errorCode_ = code;
    return *this;
  }

  OopsFieldsBuilder& setExceptionType(std::string type) {
    exceptionType_ = std::move(type);
    return *this;
  }

  OopsFieldsBuilder& setBuildRevision(std::string rev) {
    buildRevision_ = std::move(rev);
    return *this;
  }

  OopsFields build() {
    OopsFields fields;
    fields.component = std::move(component_);
    fields.errorMessage = std::move(errorMessage_);
    fields.timestamp = std::chrono::system_clock::now();
    fields.version = version_;
    fields.alpn = std::move(alpn_);
    fields.connectionId = std::move(connectionId_);
    fields.streamId = streamId_;
    fields.errorCode = errorCode_;
    fields.exceptionType = std::move(exceptionType_);
    fields.buildRevision = std::move(buildRevision_);
    return fields;
  }

 private:
  std::string component_;
  std::string errorMessage_;
  std::optional<uint32_t> version_;
  std::optional<std::string> alpn_;
  std::optional<std::string> connectionId_;
  std::optional<uint64_t> streamId_;
  std::optional<uint64_t> errorCode_;
  std::optional<std::string> exceptionType_;
  std::optional<std::string> buildRevision_;
};

} // namespace proto_oops
