//--------------------------------------------------------------------------
// Copyright (C) 2019-2019 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// rt_global_inspector.cc author davis mcpherson <davmcphe@cisco.com>

#include "rt_global_inspector.h"

#include <cstdint>
#include <ctime>

#include "flow/flow.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "time/packet_time.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

using namespace snort;

static const char* s_name = "rt_global";
static const char* s_help = "The regression test global inspector is used for regression tests specific to a global inspector";

const PegInfo rtgi_pegs[] =
{
    { CountType::SUM, "packets", "total packets" },
    { CountType::END, nullptr, nullptr }
};

THREAD_LOCAL RtGlobalInspectorStats rtgi_stats;

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter rtpi_params[] =
{
    { "memcap", Parameter::PT_INT, nullptr, "2048", "cap on amount of memory used" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

struct RtGlobalModuleConfig
{
    uint64_t memcap = 0;
};

struct RtgiCache
{
    uint64_t memcap = 0;
    uint8_t* rtgi_memory = nullptr;
};
THREAD_LOCAL RtgiCache* rtgi_cache = nullptr;

class RtGlobalReloadTuner : public ReloadResourceTuner
{
public:

    void initialize(RtGlobalModuleConfig& config_)
    { config = config_; }

    bool tinit() override
    {
        if (rtgi_cache->memcap != config.memcap)
            return true;
        else
            return false;
    }

    bool tune_packet_context() override
    {
        LogMessage("Reg Test Global module per packet configuration reload resource tuning complete\n");
        tune_resources(max_work);
        return true;
    }

    bool tune_idle_context() override
    {
        LogMessage("Reg Test Global module idle configuration reload resource tuning complete\n");
        tune_resources(max_work_idle);
        return true;
    }

private:
    bool tune_resources(unsigned work_limit)
    {
        if ( work_limit-- )
        {
            snort_free(rtgi_cache->rtgi_memory);
            rtgi_cache->rtgi_memory = (uint8_t*)snort_alloc(config.memcap);
        }

        return true;
    }

    RtGlobalModuleConfig config;
};

class RtGlobalModule : public Module
{
public:
    RtGlobalModule() : Module(s_name, s_help, rtpi_params)
    { }

    const PegInfo* get_pegs() const override
    { return rtgi_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&rtgi_stats; }

    bool set(const char*, Value& v, SnortConfig*) override;
    bool end(const char* fqn, int, SnortConfig*) override;

    const RtGlobalModuleConfig* get_data()
    { return &config; }

    Usage get_usage() const override
    { return GLOBAL; }

private:
    RtGlobalReloadTuner rtgi_reload_tuner;
    RtGlobalModuleConfig config;
};

bool RtGlobalModule::set(const char*, Value& v, SnortConfig*)
{
    if (v.is("memcap"))
        config.memcap = v.get_uint64();
    else
        return false;

    return true;
}

bool RtGlobalModule::end(const char*, int, SnortConfig* sc)
{
    rtgi_reload_tuner.initialize(config);
    sc->register_reload_resource_tuner(rtgi_reload_tuner);
    return true;
}

//-------------------------------------------------------------------------
// inspector stuff
//-------------------------------------------------------------------------

class RtGlobalInspector : public Inspector
{
public:
    RtGlobalInspector(const RtGlobalModuleConfig*);

    void eval(Packet*) override;
    void show(SnortConfig*) override;
    void tinit() override;
    void tterm() override;

public:
    RtGlobalModuleConfig config;
};

RtGlobalInspector::RtGlobalInspector(const RtGlobalModuleConfig* c)
{ config = *c; }

void RtGlobalInspector::tinit()
{
    rtgi_cache = new RtgiCache;
    rtgi_cache->memcap = config.memcap;
    rtgi_cache->rtgi_memory = (uint8_t*)snort_alloc(config.memcap);
}

void RtGlobalInspector::tterm()
{
    snort_free(rtgi_cache->rtgi_memory);
    delete rtgi_cache;
}

void RtGlobalInspector::eval(Packet*)
{
    rtgi_stats.total_packets++;
}

void RtGlobalInspector::show(SnortConfig*)
{
    LogMessage("%s config:\n", s_name);
    LogMessage("    memcap: %" PRIu64 "\n", config.memcap);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new RtGlobalModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* rtgi_ctor(Module* m)
{
    RtGlobalModule* mod = (RtGlobalModule*)m;
    return new RtGlobalInspector(mod->get_data());
}

static void rtgi_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi rtgi_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__PDU,
    nullptr, // buffers
    s_name, // service
    nullptr, // init
    nullptr, // term
    nullptr, // tinit
    nullptr, // tterm
    rtgi_ctor,
    rtgi_dtor,
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &rtgi_api.base,
    nullptr
};
