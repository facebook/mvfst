#include <quic/tools/tperf/TperfQLogger.h>

namespace quic { namespace tperf {

TperfQLogger::TperfQLogger(std::string vantagePoint, const std::string& path)
    : FileQLogger(kHTTP3ProtocolType, std::move(vantagePoint)), path_(path) {}

TperfQLogger::~TperfQLogger() {
  outputLogsToFile(path_, true /* prttyJson */);
}
}} // namespace quic::tperf
