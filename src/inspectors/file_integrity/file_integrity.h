#ifndef FILE_INTEGRITY_H
#define FILE_INTEGRITY_H

#include "framework/inspector.h"
#include "hash/hash_key_operations.h"
#include "main/snort_types.h"
#include "main/thread.h"

#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <atomic>
#include <thread>

namespace snort
{
    class SO_PUBLIC FileIntegrity : public Inspector
    {
    public:
        FileIntegrity();
        ~FileIntegrity() override;

        void show(const SnortConfig*) const override;
        void eval(Packet*) override { }

        void check_integrity();
        void tinit() override;
        void tterm() override;

        void configure(const std::vector<std::string>& paths,
                       const std::string& baseline,
                       unsigned interval,
                       bool mod, bool add, bool del);

    private:
        std::string compute_sha256(const std::string& file_path);
        void load_baseline();
        void save_baseline();
        void monitor_files();

        std::vector<std::string> monitored_paths;
        std::unordered_map<std::string, std::string> file_hashes;
        std::string baseline_file;
        unsigned int check_interval;
        bool alert_on_modification;
        bool alert_on_addition;
        bool alert_on_deletion;

        std::mutex hash_mutex;

        std::atomic<bool> running{false};
        std::thread worker;
    };
}
#endif
