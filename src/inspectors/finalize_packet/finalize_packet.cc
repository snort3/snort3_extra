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
// finalize_packet.cc author Steve Chew <stechew@sourcefire.com>

#include <ctime>

#include "detection/ips_context.h"
#include "flow/flow.h"
#include "framework/data_bus.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "protocols/packet.h"
#include "pub_sub/finalize_packet_event.h"

#include "finalize_packet_splitter.h"

using namespace snort;

static const char* s_name = "finalize_packet";
static const char* s_help = "handle the finalize packet event";

struct FinalizePacketStats
{
    PegCount pdus;
    PegCount events;
};

static THREAD_LOCAL FinalizePacketStats fp_stats;

const PegInfo fp_pegs[] =
{
    { CountType::SUM, "pdus", "total PDUs seen" },
    { CountType::SUM, "events", "total events seen" },

    { CountType::END, nullptr, nullptr }
};

//-------------------------------------------------------------------------
// Handler for finalize packet event.
//-------------------------------------------------------------------------

class FinalizePacketHandler : public DataHandler
{
public:
    FinalizePacketHandler() : DataHandler(s_name)
    { }

    void handle(DataEvent&, Flow*) override;

private:
};

void FinalizePacketHandler::handle(DataEvent& event, Flow*)
{
    FinalizePacketEvent* fp_event = (FinalizePacketEvent*)&event;
    const Packet* pkt = fp_event->get_packet();
    DAQ_Verdict verdict = fp_event->get_verdict();
    fp_stats.events++;
    LogMessage("FinalizePacketHandler::handle: received event " STDu64
        " for packet " STDu64 ", len %u. Verdict is %d.\n",
        fp_stats.events, pkt->context->packet_number, pkt->pktlen, verdict);
}

//-------------------------------------------------------------------------
// inspector stuff
//-------------------------------------------------------------------------

class FinalizePacket : public Inspector
{
public:
    FinalizePacket(uint32_t start, uint32_t end)
    {
        start_pdu = start;
        end_pdu = end;
    }

    void show(SnortConfig*) override;
    void eval(Packet* p) override
    {
        fp_stats.pdus++;
        if(start_pdu <= fp_stats.pdus and end_pdu > fp_stats.pdus)
        {
            LogMessage("FinalizePacket::eval: enable finalize packet events.\n");
            p->flow->trigger_finalize_event = true;
        }
        else
        {
            LogMessage("FinalizePacket::eval: disable finalize packet events.\n");
            p->flow->trigger_finalize_event = false;
        }
    }

    StreamSplitter* get_splitter(bool c2s) override
    { return new FinalizePacketSplitter(c2s); }

    bool configure(SnortConfig*) override
    {
        DataBus::subscribe(FINALIZE_PACKET_EVENT, new FinalizePacketHandler());
        return true;
    }

private:
    uint32_t start_pdu;
    uint32_t end_pdu;
};

void FinalizePacket::show(SnortConfig*)
{
    LogMessage("%s config:\n", s_name);
    LogMessage("    start: %u\n", start_pdu);
    LogMessage("    end: %u\n", end_pdu);
}

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter fp_params[] =
{
    { "start_pdu", Parameter::PT_INT, "0:max32", "0",
      "Register to receive finalize packet event starting on this PDU" },

    { "end_pdu", Parameter::PT_INT, "0:max32", "0",
      "Deregister for finalize packet events on this PDU" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class FinalizePacketModule : public Module
{
public:
    FinalizePacketModule() : Module(s_name, s_help, fp_params)
    { }

    const PegInfo* get_pegs() const override
    { return fp_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&fp_stats; }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value& v, SnortConfig*) override;

    Usage get_usage() const override
    { return INSPECT; }

public:
    uint32_t start_pdu;
    uint32_t end_pdu;
};

bool FinalizePacketModule::begin(const char*, int, SnortConfig*)
{
    start_pdu = 0;
    end_pdu = 0;
    return true;
}

bool FinalizePacketModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("start_pdu") )
        start_pdu = v.get_uint32();

    else if ( v.is("end_pdu") )
        end_pdu = v.get_uint32();

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new FinalizePacketModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* fp_ctor(Module* m)
{
    FinalizePacketModule* mod = (FinalizePacketModule*)m;
    return new FinalizePacket(mod->start_pdu, mod->end_pdu);
}

static void fp_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi finalize_packet_api
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
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit,
    nullptr, // tterm,
    fp_ctor,
    fp_dtor,
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &finalize_packet_api.base,
    nullptr
};

