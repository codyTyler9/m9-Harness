#include <iostream>
#include <thread>
#include <atomic>
#include "miner.h"
#include "shake_stress.h"

std::atomic<bool> g_stop{ false };

void stats_thread();

int main() {
    std::cout << "Quantum Miner Harness starting...\n";
    std::cout << "Press ENTER to stop.\n";

    std::thread miner_thread(miner_thread_func);
    std::thread stress_thread(ram_stress_thread_func);
    std::thread stats(stats_thread);

    std::cin.get();
    g_stop.store(true);

    miner_thread.join();
    stress_thread.join();
    stats.join();

    std::cout << "Stopped.\n";
    return 0;
}

void stats_thread() {
    using clock = std::chrono::steady_clock;
    auto last = clock::now();
    uint64_t last_count = 0;

    while (!g_stop.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        auto now = clock::now();
        uint64_t count = g_hash_count.load();
        double dt = std::chrono::duration<double>(now - last).count();
        double hps = (count - last_count) / dt;

        std::cout << "[STATS] " << hps << " H/s\n";

        last = now;
        last_count = count;
    }
}