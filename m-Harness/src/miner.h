#pragma once
#include <atomic>

extern std::atomic<bool> g_stop;
extern std::atomic<uint64_t> g_hash_count;

void miner_thread_func();