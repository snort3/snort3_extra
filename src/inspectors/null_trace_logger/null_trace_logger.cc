//--------------------------------------------------------------------------
// Copyright (C) 2020-2026 Cisco and/or its affiliates. All rights reserved.
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
// null_trace_logger.cc author Oleksandr Serhiienko <oserhiie@cisco.com>
//                      author Oleksii Shumeiko <oshumeik@cisco.com>

#include "framework/module.h"
#include "framework/tracer.h"
#include "trace/trace_api.h"

static const char* s_name = "null_trace_logger";
static const char* s_help = "trace logger with a null printout";

using namespace snort;

//-------------------------------------------------------------------------
// Config Parameters
//-------------------------------------------------------------------------
static const Parameter s_params[] =
{
    { "enable", Parameter::PT_BOOL, nullptr, nullptr, "enable null trace logger" },
    { nullptr,  Parameter::PT_MAX,  nullptr, nullptr, nullptr }
};

struct NullTraceConfig
{
    bool enable = false;
};

class NullTrace;

class NullTrace : public TraceLoggerPlug
{
public:
    explicit NullTrace(const NullTraceConfig& cfg) : TraceLoggerPlug(s_name), config(cfg)
    {
        set_enabled(config.enable);
    }

    void log(const char*, const char*, uint8_t, const char*, const Packet*) override
    {
    }

    void update_config(const NullTraceConfig& new_config)
    {
        config = new_config;
        set_enabled(config.enable);
    }

private:
    NullTraceConfig config;
};

//-------------------------------------------------------------------------
// Module
//-------------------------------------------------------------------------
class NullTraceModule : public Module
{
public:
    NullTraceModule() : Module(s_name, s_help, s_params) { }

    bool set(const char* name, Value& v, SnortConfig*) override
    {
        if (strcmp(name, "null_trace_logger.enable") == 0)
        {
            config.enable = v.get_bool();
            
            if (config.enable)
                TraceApi::register_enabled_tracer("null_trace_logger");
            else
                TraceApi::unregister_tracer("null_trace_logger");
        }
        return true;
    }

    bool begin(const char* fqn, int, SnortConfig*) override
    {
        if (!strcmp(fqn, "null_trace_logger"))
        {
            config.enable = true;
        }
        return true;
    }

    bool end(const char* fqn, int, SnortConfig*) override
    {
        if (!strcmp(fqn, "null_trace_logger") && trace_logger_instance)
        {
            trace_logger_instance->update_config(config);
        }
        return true;
    }

    const NullTraceConfig& get_config() const
    { return config; }

    void register_instance(NullTrace* instance)
    { trace_logger_instance = instance; }

    Usage get_usage() const override
    { return GLOBAL; }

private:
    NullTraceConfig config;
    NullTrace* trace_logger_instance = nullptr;
};

//-------------------------------------------------------------------------
// API
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new NullTraceModule; }

static void mod_dtor(Module* m)
{ delete m; }

static TraceLoggerPlug* trace_ctor(Module* m, const std::string&)
{
    NullTraceModule* mod = static_cast<NullTraceModule*>(m);
    NullTrace* logger = new NullTrace(mod->get_config());
    mod->register_instance(logger);
    return logger;
}

static void trace_dtor(TraceLoggerPlug* logger)
{ delete logger; }

static const TraceLogApi trace_api =
{
    {
        PT_TRACE,
        sizeof(TraceLogApi),
        TRACE_LOGAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    TRACE_OUTPUT_TYPE_FLAG__TRACE,
    trace_ctor,
    trace_dtor
};

const BaseApi* null_trace_logger[] =
{
    &trace_api.base,
    nullptr
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &trace_api.base,
    nullptr
};

