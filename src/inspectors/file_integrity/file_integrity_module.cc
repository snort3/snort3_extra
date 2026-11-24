// registers file integrity monitor as a Snort plugin
// Defines configuration options that users can set
// Parses Snort configuration into usable values
// Creates the monitoring inspector with those settings
// Registers as a Snort plugin for automatic loading
// Handles the complete lifecycle of the module

#include "file_integrity_module.h"
#include "file_integrity.h"

#include "framework/module.h"
#include "framework/parameter.h"
#include "framework/inspector.h"
#include "main/snort_types.h"
#include "protocols/packet.h"


using namespace snort;

// configuration parameters for the module
// { name, type, range, default, description }
static const Parameter file_integrity_params[] =
{
    { "baseline_file",         Parameter::PT_STRING, nullptr, nullptr,
      "file to store baseline hashes" },

    { "monitored_paths",       Parameter::PT_STRING, nullptr, nullptr,
      "comma-separated files or directories to monitor" },

    { "check_interval",        Parameter::PT_INT,    "1:86400", "60",
      "integrity check interval in seconds" },

    { "alert_on_modification", Parameter::PT_BOOL,   nullptr, "true",
      "alert when files are modified" },

    { "alert_on_addition",     Parameter::PT_BOOL,   nullptr, "true",
      "alert when new files are added" },

    { "alert_on_deletion",     Parameter::PT_BOOL,   nullptr, "true",
      "alert when files are deleted" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

// no rules to register
static const RuleMap file_integrity_rules[] =
{
    { 0, nullptr }
};

// No counters are exposed
static const PegInfo file_integrity_pegs[] =
{
    { CountType::END, nullptr, nullptr }
};

// Construct the module, {internal name, pretty name, parameter schema table}
FileIntegrityModule::FileIntegrityModule() : 
    Module("file_integrity", "file_integrity", file_integrity_params)
{
}

// Splits a comma-separated string (like "a,b,c") into a vector of strings
static inline void split_csv(const char* csv, std::vector<std::string>& out)
{
    if (!csv) return;
    std::string s(csv);
    size_t start = 0;
    while (start < s.size())
    {
        size_t comma = s.find(',', start);
        std::string item = s.substr(start, (comma == std::string::npos) ? std::string::npos : (comma - start));
        size_t l = item.find_first_not_of(" \t\r\n");
        size_t r = item.find_last_not_of(" \t\r\n");
        if (l != std::string::npos)
            out.emplace_back(item.substr(l, r - l + 1));
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
}

bool FileIntegrityModule::set(const char*, Value& v, SnortConfig*)
{
    if (v.is("baseline_file"))
        baseline_file = v.get_string();

    else if (v.is("monitored_paths"))
    {
        std::vector<std::string> tmp;
        split_csv(v.get_string(), tmp);
        monitored_paths.insert(monitored_paths.end(), tmp.begin(), tmp.end());
    }

    else if (v.is("check_interval"))
        check_interval = v.get_uint32();

    else if (v.is("alert_on_modification"))
        alert_on_modification = v.get_bool();

    else if (v.is("alert_on_addition"))
        alert_on_addition = v.get_bool();

    else if (v.is("alert_on_deletion"))
        alert_on_deletion = v.get_bool();

    else
        return false;

    return true;
}



bool FileIntegrityModule::begin(const char*, int, SnortConfig*)
{
    return true;
}

bool FileIntegrityModule::end(const char*, int, SnortConfig*)
{
    return true;
}

// statistics information
const PegInfo* FileIntegrityModule::get_pegs() const
{
    return file_integrity_pegs;
}

PegCount* FileIntegrityModule::get_counts() const
{
    return nullptr;
}

ProfileStats* FileIntegrityModule::get_profile() const
{
    return nullptr;
}

// creating and destroying the module
static Module* mod_ctor()
{
    return new FileIntegrityModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

// inspector instance
static Inspector* file_integrity_ctor(Module* m)
{
    auto* mod = static_cast<FileIntegrityModule*>(m);
    auto* fi  = new FileIntegrity();

    fi->configure(mod->monitored_paths,
                  mod->baseline_file,
                  mod->check_interval ? mod->check_interval : 60,
                  mod->alert_on_modification,
                  mod->alert_on_addition,
                  mod->alert_on_deletion);

    return fi;
}




static void file_integrity_dtor(Inspector* p)
{
    delete p;
}

// plugin API structure that Snort uses to load the module
static const InspectApi file_integrity_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        "file_integrity",
        "File Integrity Monitoring Inspector",
        mod_ctor,
        mod_dtor
    },
    IT_PASSIVE,
    PROTO_BIT__NONE,
    nullptr,
    nullptr, 
    nullptr,
    nullptr,
    nullptr, 
    nullptr, 
    file_integrity_ctor,
    file_integrity_dtor,
    nullptr, 
    nullptr 
};


// Exports the plugin for dynamic loading (BUILDING_SO) or static linking
#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &file_integrity_api.base,
    nullptr
};
#else
const BaseApi* sin_file_integrity = &file_integrity_api.base;
#endif

