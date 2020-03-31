//--------------------------------------------------------------------------
// Copyright (C) 2019-2020 Cisco and/or its affiliates. All rights reserved.
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
// rt_packet_inspector.cc author davis mcpherson <davmcphe@cisco.com>

#include "rt_packet_inspector.h"

#include <ctime>

#include "flow/expect_cache.h"
#include "flow/flow.h"
#include "framework/data_bus.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "packet_io/active.h"
#include "pub_sub/expect_events.h"
#include "time/packet_time.h"
#include "utils/util_cstring.h"

using namespace snort;

static const char* s_name = "rt_packet";
static const char* s_help = "The regression test packet inspector is used when special packet handling is required for a reg test";

const PegInfo rtpi_pegs[] =
{
    { CountType::SUM, "packets", "total packets" },
    { CountType::SUM, "retry_requests", "total retry packets requested" },
    { CountType::SUM, "retry_packets", "total retried packets received" },
    { CountType::END, nullptr, nullptr }
};

THREAD_LOCAL RtPacketInspectorStats rtpi_stats;

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter rtpi_params[] =
{
    { "retry_targeted", Parameter::PT_BOOL, nullptr, "false",
        "request retry for packets whose data starts with 'A'" },

    { "retry_all", Parameter::PT_BOOL, nullptr, "false",
        "request retry for all non-retry packets" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class RtPacketInspectorModule : public Module
{
public:
    RtPacketInspectorModule() : Module(s_name, s_help, rtpi_params)
    { }

    const PegInfo* get_pegs() const override
    { return rtpi_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&rtpi_stats; }

    bool set(const char*, Value& v, SnortConfig*) override;

    bool is_retry_targeted() { return retry_targeted; }
    bool is_retry_all() { return retry_all; }

public:
    bool retry_targeted = false;
    bool retry_all = false;
};

bool RtPacketInspectorModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("retry_targeted") )
        retry_targeted = v.get_bool();
    else if ( v.is("retry_all") )
        retry_all = v.get_bool();
    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// flow data stuff
//-------------------------------------------------------------------------
class RtPacketInspectorFlowData : public FlowData
{
public:
    RtPacketInspectorFlowData();
    ~RtPacketInspectorFlowData() override;
    static void init()
    { inspector_id = FlowData::create_flow_data_id(); }

    void handle_expected(Packet*) override;
    size_t size_of() override
    { return sizeof(*this); }

public:
    static unsigned inspector_id;
    unsigned test_id;
    static unsigned test_id_counter;
};

unsigned RtPacketInspectorFlowData::inspector_id = 0;
unsigned RtPacketInspectorFlowData::test_id_counter = 100;

RtPacketInspectorFlowData::RtPacketInspectorFlowData() : FlowData(inspector_id)
{
    test_id = test_id_counter++;
}

RtPacketInspectorFlowData::~RtPacketInspectorFlowData()
{
    LogMessage("RtPacketInspector: delete flow data, test_id=%d\n", test_id);
}

void RtPacketInspectorFlowData::handle_expected(Packet*)
{
    LogMessage("RtPacketInspector: handle expected, test_id=%d\n", test_id);
}

//-------------------------------------------------------------------------
// event handler stuff
//-------------------------------------------------------------------------
#define LOG_BUFF_SIZE 1024
class ExpectEventHandler : public DataHandler
{
public:
    ExpectEventHandler() : DataHandler(s_name) { }

    void handle(DataEvent&, Flow*) override;
};


void ExpectEventHandler::handle(DataEvent& event, Flow*)
{
    ExpectEvent* expect_event = (ExpectEvent*)&event;
    char cstr[INET6_ADDRSTRLEN], sstr[INET6_ADDRSTRLEN];
    expect_event->get_packet()->flow->client_ip.ntop(cstr, sizeof(cstr));
    expect_event->get_packet()->flow->server_ip.ntop(sstr, sizeof(sstr));
    LogMessage("RtPacketInspector: received expect event. packet %s:%d -> %s:%d\n",
        cstr, expect_event->get_packet()->flow->client_port,
        sstr, expect_event->get_packet()->flow->server_port);
    ExpectFlow* flow = expect_event->get_expect_flow();
    if (flow->get_flow_data(RtPacketInspectorFlowData::inspector_id) == nullptr)
    {
        RtPacketInspectorFlowData* fd = new RtPacketInspectorFlowData();
        LogMessage("RtPacketInspector: created a new flow data, test_id=%u, adding ... ", fd->test_id);
        unsigned added_test_id = fd->test_id;
        flow->add_flow_data(fd);
        fd = (RtPacketInspectorFlowData*)flow->get_flow_data(RtPacketInspectorFlowData::inspector_id);
        if (fd && fd->test_id == added_test_id)
            LogMessage("succeed!\n");
        else
            LogMessage("failed!\n");
    }

    char buff[LOG_BUFF_SIZE];
    safe_snprintf(buff, LOG_BUFF_SIZE, "Expected flows triggered by packet:");
    std::vector<ExpectFlow*>* expected_flows = ExpectFlow::get_expect_flows();
    if(expected_flows)
    {
        for (auto ef : *expected_flows)
        {
            RtPacketInspectorFlowData* fd = (RtPacketInspectorFlowData*)ef->get_flow_data(RtPacketInspectorFlowData::inspector_id);
            if (fd)
               sfsnprintfappend(buff, LOG_BUFF_SIZE, " %u", fd->test_id);
        }
    }
    LogMessage("%s\n", buff);
}

//-------------------------------------------------------------------------
// inspector stuff
//-------------------------------------------------------------------------

class RtPacketInspector : public Inspector
{
public:
    RtPacketInspector(RtPacketInspectorModule* mod);

    void show(SnortConfig*) override;
    void eval(Packet* p) override;
    bool configure(SnortConfig*) override
    {
        DataBus::subscribe(EXPECT_EVENT_TYPE_EARLY_SESSION_CREATE_KEY, new ExpectEventHandler());
        return true;
    }

private:
    bool retry_targeted;
    bool retry_all;
    void do_packet_retry_test(Packet* p);
};

RtPacketInspector::RtPacketInspector(RtPacketInspectorModule* mod)
{
    retry_targeted = mod->is_retry_targeted();
    retry_all = mod->is_retry_all();
    rtpi_stats.total_packets = 0;
}

void RtPacketInspector::show(SnortConfig*)
{
    ConfigLogger::log_flag("retry_targeted", retry_targeted);
    ConfigLogger::log_flag("retry_all", retry_all);
}

void RtPacketInspector::eval(Packet* p)
{
    do_packet_retry_test(p);

    rtpi_stats.total_packets++;
}

void RtPacketInspector::do_packet_retry_test(Packet* p)
{
    if (retry_all || (retry_targeted && p->dsize && p->data[0] == 'A'))
    {
        if (!p->is_retry())
        {
            p->active->retry_packet(p);
            rtpi_stats.retry_requests++;
        }
        else
            rtpi_stats.retry_packets++;
    }
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------
static void reg_test_init()
{
    RtPacketInspectorFlowData::init();
}

static Module* mod_ctor()
{ return new RtPacketInspectorModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* rti_ctor(Module* m)
{ return new RtPacketInspector((RtPacketInspectorModule*)m); }

static void rti_dtor(Inspector* p)
{ delete p; }

static const InspectApi rtpi_api
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
    IT_PACKET,
    PROTO_BIT__ANY_IP,
    nullptr, // buffers
    s_name,  // service
    reg_test_init, // pinit
    nullptr, // pterm
    nullptr, // tinit,
    nullptr, // tterm,
    rti_ctor,
    rti_dtor,
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &rtpi_api.base,
    nullptr
};

