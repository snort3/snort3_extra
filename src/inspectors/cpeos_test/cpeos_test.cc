//--------------------------------------------------------------------------
// Copyright (C) 2021-2023 Cisco and/or its affiliates. All rights reserved.
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

// cpeos_test.cc author Arun Prasad Mandava <armandav@cisco.com>

#include "flow/flow.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "network_inspectors/rna/rna_cpe_os.h"
#include "protocols/eth.h"
#include "protocols/packet.h"
#include "pub_sub/external_event_ids.h"

using namespace snort;

static const char* s_name = "cpeos_test";
static const char* s_help = "for testing CPE OS RNA event generation";

//-------------------------------------------------------------------------
// inspector stuff
//-------------------------------------------------------------------------

class CpeOsTest : public Inspector
{
public:
    CpeOsTest() = default;
    void eval(Packet*) override;
    bool configure(SnortConfig*) override;

private:
    unsigned pub_id = 0;
};

bool CpeOsTest::configure(SnortConfig*)
{
    pub_id = DataBus::get_id(external_pub_key);
    return true;
}

void CpeOsTest::eval(Packet* p)
{
    CpeOsInfoEvent cpe(*p);
    cpe.add_os("cpe:2.3:o:microsoft:windows_10:1507:*:*:*:*:*:*:*");
    cpe.add_os("cpe:2.3:o:microsoft:windows_10:1703:*:*:*:*:*:*:*");
    DataBus::publish(pub_id, ExternalEventIds::CPE_OS_INFO, cpe, p->flow);
}

class CpeOsTestModule : public Module
{
public:
    CpeOsTestModule() : Module(s_name, s_help)
    { }
};

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new CpeOsTestModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* mt_ctor(Module*)
{ return new CpeOsTest; }

static void mt_dtor(Inspector* p)
{ delete p; }

static const InspectApi cpeos_api
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
    IT_CONTROL,
    PROTO_BIT__TCP,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit,
    nullptr, // tterm,
    mt_ctor,
    mt_dtor,
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &cpeos_api.base,
    nullptr
};
