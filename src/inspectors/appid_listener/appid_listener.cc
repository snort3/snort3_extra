//--------------------------------------------------------------------------
// Copyright (C) 2020-2024 Cisco and/or its affiliates. All rights reserved.
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
// appid_listener.cc author Rajeshwari Adapalam <rajadapa@cisco.com>

#include "appid_listener.h"

#include <ctime>

#include "framework/decode_data.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "main/snort_config.h"
#include "main/snort_types.h"
#include "profiler/profiler.h"
#include "pub_sub/appid_event_ids.h"
#include "pub_sub/http_events.h"
#include "time/packet_time.h"

#include "appid_listener_event_handler.h"

using namespace snort;

static const char* s_help = "log selected published data to appid_listener.log";

static const Parameter s_params[] =
{
    { "json_logging", Parameter::PT_BOOL, nullptr, "false",
        "log appid data in json format" },
    { "file", Parameter::PT_STRING, nullptr, nullptr,
        "output data to given file" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class AppIdListenerModule : public Module
{
public:
    AppIdListenerModule() : Module(MOD_NAME, s_help, s_params) { }

    ~AppIdListenerModule() override
    {
        delete config;
    }

    bool begin(const char*, int, SnortConfig*) override
    {
        if ( config )
            return false;

        config = new AppIdListenerConfig;
        return true;
    }

    bool set(const char*, Value& v, SnortConfig*) override
    {
        if ( v.is("json_logging") )
            config->json_logging = v.get_bool();
        else if ( v.is("file") )
            config->file_name = v.get_string();

        return true;
    }

    AppIdListenerConfig* get_data()
    {
        AppIdListenerConfig* temp = config;
        config = nullptr;
        return temp;
    }

private:
    AppIdListenerConfig* config = nullptr;
};

//-------------------------------------------------------------------------
// inspector stuff
//-------------------------------------------------------------------------

class AppIdListenerInspector : public Inspector
{
public:
    AppIdListenerInspector(AppIdListenerModule& mod)
    {
        config = mod.get_data();
        assert(config);
    }

    ~AppIdListenerInspector() override
    { delete config; }

    void eval(Packet*) override { }

    bool configure(SnortConfig* sc) override
    {
        assert(config);
        sc->set_run_flags(RUN_FLAG__TRACK_ON_SYN);
        if (!config->file_name.empty())
        {
            config->file_stream.open(config->file_name);
            if (!config->file_stream.is_open())
                WarningMessage("appid_listener: can't open file %s\n", config->file_name.c_str());
        }
        DataBus::subscribe_network(appid_pub_key, AppIdEventIds::ANY_CHANGE, new AppIdListenerEventHandler(*config));
        return true;
    }

private:
    AppIdListenerConfig* config = nullptr;
};

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new AppIdListenerModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static Inspector* al_ctor(Module* m)
{
    assert(m);
    return new AppIdListenerInspector((AppIdListenerModule&)*m);
}

static void al_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi appid_lstnr_api
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        MOD_NAME,
        s_help,
        mod_ctor,
        mod_dtor
    },
    IT_PASSIVE,
    PROTO_BIT__NONE,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit,
    nullptr, // tterm,
    al_ctor,
    al_dtor,
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &appid_lstnr_api.base,
    nullptr
};
