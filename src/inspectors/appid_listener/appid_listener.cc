//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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

#include <ctime>

#include "flow/flow.h"
#include "framework/data_bus.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "main/snort_types.h"
#include "network_inspectors/appid/appid_api.h"
#include "profiler/profiler.h"
#include "pub_sub/http_events.h"
#include "pub_sub/appid_events.h"
#include "time/packet_time.h"
#include "utils/stats.h"

static const char* s_name = "appid_listener";
static const char* s_help = "log selected published data to appid_listener.log";

using namespace snort;


//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

class AppIdListenerModule : public Module
{
public:
    AppIdListenerModule() : Module(s_name, s_help){ }
};


// //-------------------------------------------------------------------------
// // data handler stuff
// //-------------------------------------------------------------------------

class AppIdEventHandler : public DataHandler
{
public:
    AppIdEventHandler() : DataHandler(s_name){ }

    void handle(DataEvent& event, Flow* flow) override
    {
        if (!flow)
        {
            LogMessage("the flow in handle() is empty\n");
            return;
        }

        AppidEvent* appid_event = static_cast<AppidEvent*>(&event);
        const AppidChangeBits& ac_bits = appid_event->get_change_bitset();
        const AppIdSessionApi& api = appid_event->get_appid_session_api();

        if (ac_bits.test(APPID_SERVICE_BIT) or ac_bits.test(APPID_CLIENT_BIT) or 
            ac_bits.test(APPID_PAYLOAD_BIT) or ac_bits.test(APPID_MISC_BIT) or 
            ac_bits.test(APPID_REFERRED_BIT)) 
        {
            char cli_ip_str[INET6_ADDRSTRLEN], srv_ip_str[INET6_ADDRSTRLEN];                                            
            flow->client_ip.ntop(cli_ip_str, sizeof(cli_ip_str));                           
            flow->server_ip.ntop(srv_ip_str, sizeof(srv_ip_str));            

            AppId service, payload, client, misc, referred;
            payload = api.get_payload_app_id();
            client = api.get_client_app_id();
            misc = api.get_misc_app_id();
            service = api.get_service_app_id();
            referred = api.get_referred_app_id();

            LogMessage("%s:%d<->%s:%d proto: %d packet: " STDu64 " service: %d client: %d "
                "payload: %d misc: %d referred: %d\n",
                cli_ip_str, flow->client_port, srv_ip_str, flow->server_port, flow->ip_proto,
                get_packet_number(), service, client, payload, misc, referred);
        }
        else
        {
            LogMessage("AppId is not available\n");
        }
    }
};


//-------------------------------------------------------------------------
// inspector stuff
//-------------------------------------------------------------------------

class AppIdListenerInspector : public Inspector
{
public:
    void eval(Packet*) override { }
    bool configure(SnortConfig* sc) override
    {
        sc->set_run_flags(RUN_FLAG__TRACK_ON_SYN);
        DataBus::subscribe(APPID_EVENT_ANY_CHANGE, new AppIdEventHandler());
        return true;
    }
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

static Inspector* al_ctor(Module*)
{
    return new AppIdListenerInspector();
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
        s_name,
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

