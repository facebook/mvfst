#include <cstdint>

extern "C" {
bool *ccp_create_handle();
void ccp_spawn(const char* args, uint32_t log_fd, uint64_t uid, bool *handle);
void ccp_kill(bool *handle);
}
