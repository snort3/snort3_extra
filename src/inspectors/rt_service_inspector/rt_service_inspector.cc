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
// rt_service_inspector.cc author davis mcpherson <davmcphe@cisco.com>

#include "rt_service_inspector.h"

#include "flow/flow.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "main/snort_config.h"

#include "rt_service_inspector_splitter.h"

using namespace snort;
static const char* s_name = "rt_service";
static const char* s_help = "The regression test service inspector is used by regression tests that require custom service inspector support.";

const PegInfo rtsi_pegs[] =
{
    { CountType::SUM, "packets", "total packets" },
    { CountType::SUM, "flush_requests", "total splitter flush requests" },
    { CountType::SUM, "hold_requests", "total splitter hold requests" },
    { CountType::SUM, "search_requests", "total splitter search requests" },
    { CountType::END, nullptr, nullptr }
};

THREAD_LOCAL RtServiceInspectorStats rtsi_stats;

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter rtsi_params[] =
{
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class RtServiceInspectorModule : public Module
{
public:
    RtServiceInspectorModule() : Module(s_name, s_help, rtsi_params) { }

    const PegInfo* get_pegs() const override
    { return rtsi_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&rtsi_stats; }
};

//-------------------------------------------------------------------------
// flow data stuff
//-------------------------------------------------------------------------
class RtServiceInspectorFlowData : public FlowData
{
public:
    RtServiceInspectorFlowData();
    ~RtServiceInspectorFlowData() override;

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

unsigned RtServiceInspectorFlowData::inspector_id = 0;
unsigned RtServiceInspectorFlowData::test_id_counter = 100;

RtServiceInspectorFlowData::RtServiceInspectorFlowData() : FlowData(inspector_id)
{
    test_id = test_id_counter++;
}

RtServiceInspectorFlowData::~RtServiceInspectorFlowData()
{
    LogMessage("Reg Test Service Inspector: delete flow data, test_id=%d\n", test_id);
}

void RtServiceInspectorFlowData::handle_expected(Packet*)
{
    LogMessage("Reg Test Service Inspector: handle expected, test_id=%d\n", test_id);
}

//-------------------------------------------------------------------------
// inspector stuff
//-------------------------------------------------------------------------

class RtServiceInspector : public Inspector
{
public:
    RtServiceInspector(RtServiceInspectorModule* mod);

    void eval(Packet* p) override;
    bool configure(SnortConfig*) override
    { return true; }

    StreamSplitter* get_splitter(bool to_server) override;
};

RtServiceInspector::RtServiceInspector(RtServiceInspectorModule*)
{
    rtsi_stats.total_packets = 0;
}

void RtServiceInspector::eval(Packet*)
{
    rtsi_stats.total_packets++;
}

StreamSplitter* RtServiceInspector::get_splitter(bool to_server)
{
    return new RegTestSplitter(to_server);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------
static void reg_test_init()
{
    RtServiceInspectorFlowData::init();
}

static Module* mod_ctor()
{ return new RtServiceInspectorModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* rti_ctor(Module* m)
{ return new RtServiceInspector((RtServiceInspectorModule*)m); }

static void rti_dtor(Inspector* p)
{ delete p; }

static const InspectApi rtsi_aip
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
    PROTO_BIT__ANY_PDU,
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
    &rtsi_aip.base,
    nullptr
};

