#ifndef FILE_INTEGRITY_MODULE_H
#define FILE_INTEGRITY_MODULE_H

#include "framework/module.h"
#include "framework/parameter.h"
#include <string>
#include <vector>

namespace snort
{
    class FileIntegrityModule : public Module
    {
    public:
        FileIntegrityModule();
        ~FileIntegrityModule() override = default;

        bool set(const char*, Value&, SnortConfig*) override;
        bool begin(const char*, int, SnortConfig*) override;
        bool end(const char*, int, SnortConfig*) override;

        const PegInfo* get_pegs() const override;  // array of counters/metrics
        PegCount* get_counts() const override;  // actual storage
        ProfileStats* get_profile() const override; // profiling stats (timings, counts)

        Usage get_usage() const override { return INSPECT; }

        std::vector<std::string> monitored_paths; // list of filesystem paths watch for integrity changes
        std::string baseline_file = "file_integrity_baseline.txt";
        unsigned int check_interval = 60; // How often (in seconds) perform integrity checks
        bool alert_on_modification = true;
        bool alert_on_addition = true;
        bool alert_on_deletion = true;
    };
}
#endif
