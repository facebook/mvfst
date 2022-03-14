/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/BbrTesting.h>

namespace quic {

constexpr uint64_t kProbabilityThreshold = 75;
constexpr uint64_t kNoCapacityPredictionCountThreshold = 100;

BbrTestingCongestionController::BbrTestingCongestionController(
    QuicConnectionStateBase& conn)
    : BbrCongestionController(conn) {
  // Simulate 40 token bucket configurations with rates
  // from 250 kbps to 10 Mbps every 250 kbps. For each
  // configuration, the burst size is 1 second worth of bytes.
  // TODO: This list should be trimmed down.
  for (auto rate = 31250; rate <= 1250000; rate += 31250) {
    simulatedTBFVec_.emplace_back(rate, rate);
  }

  // Disable the ack aggregation logic
  BbrCongestionController::setExperimental(true);
  if (conn_.pacer) {
    conn_.pacer->setExperimental(true);
  }
}

// Limit the bandwidth based upon the measured TBF data.
// If we have a simulated token bucket with probability>kProbabilityThreshold,
// bandwdith estimate =
// max(min(tbf_rate,long_term_bw_sampler_rate),short_term_sampler_rate)
// This allows the returned bandwidth value to:
// - Continue working normally when probability is low in any Token Bucket
//   config
// - React to long-term drops in available bandwidth
// - Make use of higher short-term bandwidth bursts
// - Use the detected token bucket config otherwise
// Note that due to using short_term_sampler_rate, we could continue
// sending at a rate faster than that of the policer even after the burst has
// expired. This can last for a maximum of 1-rtt. We can try to improve
// on that later.
Bandwidth BbrTestingCongestionController::bandwidth() const noexcept {
  const SimulatedTBF* maxTBF = &simulatedTBFVec_.front();
  for (const auto& stbf : simulatedTBFVec_) {
    if (stbf.probability > maxTBF->probability) {
      maxTBF = &stbf;
    }
  }
  if (maxTBF->probability > kProbabilityThreshold) {
    return std::max(
        std::min(
            bandwidthSampler_->getBandwidth(),
            Bandwidth(maxTBF->rateBytesPerSecond, 1s)),
        bandwidthSampler_->getLatestSample());
  } else {
    return BbrCongestionController::bandwidth();
  }
}

void BbrTestingCongestionController::onPacketSent(
    const OutstandingPacket& packet) {
  BbrCongestionController::onPacketSent(packet);

  if (packet.packet.header.getPacketNumberSpace() !=
      PacketNumberSpace::AppData) {
    return;
  }
  auto packetNum = packet.packet.header.getPacketSequenceNum();
  auto maybeCreatedStatusVecItr = outstandingPacketTBFStatusMap_.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(packetNum),
      std::forward_as_tuple());
  // This should be a new key. A packet cannot be sent twice.
  CHECK(maybeCreatedStatusVecItr.second);
  auto& packetTBFStatus = maybeCreatedStatusVecItr.first->second;
  packetTBFStatus.reserve(simulatedTBFVec_.size());
  auto pktSize = packet.metadata.encodedSize;
  for (auto& stbf : simulatedTBFVec_) {
    auto maybeQueueTime = stbf.tbf.consumeWithBorrowNonBlocking(
        pktSize, stbf.rateBytesPerSecond, stbf.burstBytes);
    auto hasCapacity = maybeQueueTime.value_or(0) == 0;
    packetTBFStatus.push_back(hasCapacity);
    if (!hasCapacity) {
      ++stbf.noCapacityPredictionCount;
    }
  }
}

void BbrTestingCongestionController::onPacketAckOrLoss(
    const AckEvent* FOLLY_NULLABLE ackEvent,
    const LossEvent* FOLLY_NULLABLE lossEvent) {
  BbrCongestionController::onPacketAckOrLoss(ackEvent, lossEvent);
  if (ackEvent) {
    for (const auto& ackedPacket : ackEvent->ackedPackets) {
      // Get the status of all the tested TBFs
      auto tbfStatsVecItr =
          outstandingPacketTBFStatusMap_.find(ackedPacket.packetNum);
      if (tbfStatsVecItr == outstandingPacketTBFStatusMap_.end()) {
        continue;
      }
      auto tbfStatsVec = std::move(tbfStatsVecItr->second);
      outstandingPacketTBFStatusMap_.erase(tbfStatsVecItr);

      // Check the TB predictions against the rateSample from this ack
      // Note: this uses the latest sample from the whole ack. I.e., one sample
      //       is used for all the packets acked. This may not be the
      //       accurate bandwidth measurement for all of them. Worst case,
      //       this will delay our ability to detect the TB configuration by
      //       1-rtt after its burst has ended.
      auto bwSample = bandwidthSampler_->getLatestSample().normalize();
      CHECK_EQ(tbfStatsVec.size(), simulatedTBFVec_.size());
      for (size_t i = 0; i < tbfStatsVec.size(); i++) {
        auto& stbf = simulatedTBFVec_[i];
        auto ackToTBFRatePercent = (bwSample * 100 / stbf.rateBytesPerSecond);
        // A TB prediction is true if one of these two conditions are met:
        // 1. The TB had tokens when the packet was sent and the ackRate is >
        // the rate of the TB (within 10%)
        // 2. The TB had no tokens when the packet was sent and the ackRate is
        // equal to the rate of the TB (within 10%)
        const bool stbfHadTokensOnSend = tbfStatsVec[i];
        if (stbfHadTokensOnSend) {
          if (ackToTBFRatePercent > 90) {
            stbf.correctPredictionCount++;
          } else {
            stbf.incorrectPredictionCount++;
          }
        } else {
          if (ackToTBFRatePercent > 90 && ackToTBFRatePercent < 110) {
            stbf.correctPredictionCount++;
          } else {
            stbf.incorrectPredictionCount++;
          }
        }

        if (stbf.noCapacityPredictionCount >
            kNoCapacityPredictionCountThreshold) {
          // We've hit the capacity of this token bucket enough times to
          // calculate its probability
          stbf.probability = (stbf.correctPredictionCount * 100) /
              (stbf.correctPredictionCount + stbf.incorrectPredictionCount);
          if (stbf.probability > kProbabilityThreshold) {
            btlbwFound_ = true;
          }
        }
      }
    }
  }

  if (lossEvent) {
    for (auto lostPktNum : lossEvent->lostPacketNumbers) {
      outstandingPacketTBFStatusMap_.erase(lostPktNum);
    }
  }
}
} // namespace quic
