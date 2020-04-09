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
// finalize_packet.cc author Steve Chew <stechew@sourcefire.com>

#include <daq.h>
#include <ctime>
#include <string>

#include "detection/ips_context.h"
#include "flow/flow.h"
#include "framework/data_bus.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "protocols/packet.h"
#include "pub_sub/daq_message_event.h"
#include "pub_sub/finalize_packet_event.h"
#include "stream/stream.h"

#include "finalize_packet_splitter.h"

using namespace snort;

static const char* s_name = "finalize_packet";
static const char* s_help = "handle the finalize packet event";

struct FinalizePacketStats
{
    PegCount pdus;
    PegCount events;
    PegCount other_messages;
};

static THREAD_LOCAL FinalizePacketStats fp_stats;
static THREAD_LOCAL DAQ_Verdict modify_verdict = MAX_DAQ_VERDICT;

const PegInfo fp_pegs[] =
{
    { CountType::SUM, "pdus", "total PDUs seen" },
    { CountType::SUM, "events", "total events seen" },
    { CountType::SUM, "other_messages", "total other message seen" },

    { CountType::END, nullptr, nullptr }
};

static const char* to_string(DAQ_Verdict v)
{
    switch (v)
    {
    case DAQ_VERDICT_PASS:
        return "pass";
    case DAQ_VERDICT_BLOCK:
        return "block";
    case DAQ_VERDICT_REPLACE:
        return "replace";
    case DAQ_VERDICT_WHITELIST:
        return "whitelist";
    case DAQ_VERDICT_BLACKLIST:
        return "blacklist";
    case DAQ_VERDICT_IGNORE:
        return "ignore";
    case DAQ_VERDICT_RETRY:
        return "retry";
    case MAX_DAQ_VERDICT:
    default:
        return "";
    }
}

//-------------------------------------------------------------------------
// inspector stuff
//-------------------------------------------------------------------------

class FinalizePacket : public Inspector
{
public:
    FinalizePacket(uint32_t start, uint32_t end, uint32_t modify, DAQ_Verdict verdict, bool wiz, bool direct_inject, bool defer_wlist, bool force_wlist)
    {
        start_pdu = start;
        end_pdu = end;
        modify_pdu = modify;
        new_verdict = verdict;
        switch_to_wizard = wiz;
        use_direct_inject = direct_inject;
        defer_whitelist = defer_wlist;
        force_whitelist = force_wlist;
    }

    void show(SnortConfig*) override;
    void eval(Packet* p) override
    {
        if(!p or !p->flow)
            return;

        if(defer_whitelist)
        {
            p->flow->set_deferred_whitelist(WHITELIST_DEFER_ON);
            defer_whitelist = false;    // Only turn on once.
        }

        if(force_whitelist)
        {
            // Only whitelist one packet.
            p->flow->set_ignore_direction(SSN_DIR_BOTH);
            force_whitelist = false;
        }

        fp_stats.pdus++;
        if(start_pdu <= fp_stats.pdus and end_pdu > fp_stats.pdus)
        {
            LogMessage("FinalizePacket::eval: enable finalize packet events.\n");
            p->flow->flags.trigger_finalize_event = true;
            if ( modify_pdu == fp_stats.pdus )
            {
                modify_verdict = new_verdict;
            }
        }
        else
        {
            LogMessage("FinalizePacket::eval: disable finalize packet events.\n");
            p->flow->flags.trigger_finalize_event = false;
        }
    }

    StreamSplitter* get_splitter(bool c2s) override
    { return new FinalizePacketSplitter(c2s); }

    bool configure(SnortConfig*) override;
    bool need_to_switch_wizard() { return switch_to_wizard; }
    bool need_to_use_direct_inject() { return use_direct_inject; }
private:
    uint32_t start_pdu;
    uint32_t end_pdu;
    uint32_t modify_pdu;
    DAQ_Verdict new_verdict;
    bool switch_to_wizard;
    bool use_direct_inject;
    bool defer_whitelist;
    bool force_whitelist;
};

//-------------------------------------------------------------------------
// Handler for finalize packet event.
//-------------------------------------------------------------------------
class FinalizePacketHandler : public DataHandler
{
public:
    FinalizePacketHandler(FinalizePacket& p) : DataHandler(s_name), fin_packet(p)
    { }

    void handle(DataEvent&, Flow*) override;

private:
    FinalizePacket& fin_packet;
};

void FinalizePacketHandler::handle(DataEvent& event, Flow*)
{
    FinalizePacketEvent* fp_event = (FinalizePacketEvent*)&event;
    const Packet* pkt = fp_event->get_packet();
    DAQ_Verdict& verdict = fp_event->get_verdict();
    if ( modify_verdict != MAX_DAQ_VERDICT )
    {
        LogMessage("FinalizePacketHandler::handle: changed verdict for packet " STDu64
            ", len %u. Verdict changed from %d to %d.\n",
            pkt->context->packet_number, pkt->pktlen, verdict, modify_verdict);
        verdict = modify_verdict;
        modify_verdict = MAX_DAQ_VERDICT;
    }
    fp_stats.events++;
    LogMessage("FinalizePacketHandler::handle: received event " STDu64
        " for packet " STDu64 ", len %u. Verdict is %d.\n",
        fp_stats.events, pkt->context->packet_number, pkt->pkth->pktlen, verdict);

    if ( fin_packet.need_to_use_direct_inject() )
    {
        LogMessage("FinalizePacketHandler::handle: using ioctl to inject\n");
        pkt->flow->flags.use_direct_inject = true;
    }

    if ( fin_packet.need_to_switch_wizard() )
    {
        pkt->flow->set_deferred_whitelist(WHITELIST_DEFER_DONE);
        pkt->flow->set_ignore_direction(SSN_DIR_NONE);
        pkt->flow->set_proxied();
        pkt->flow->flags.trigger_finalize_event = false;
        LogMessage("FinalizePacketHandler::handle: switching to wizard\n");
        // FIXIT-L remove const_cast by removing the const from event->get_packet()
        pkt->flow->set_service(const_cast<Packet*> (pkt), nullptr);
    }
}

//-------------------------------------------------------------------------
// Handler for other message event.
//-------------------------------------------------------------------------
class OtherMessageHandler : public DataHandler
{
public:
    OtherMessageHandler() : DataHandler(s_name)
    { }

    void handle(DataEvent&, Flow*) override;
};

void OtherMessageHandler::handle(DataEvent& event, Flow*)
{
    DaqMessageEvent* dme = (DaqMessageEvent*)&event;

    dme->set_verdict(DAQ_VERDICT_IGNORE);
    fp_stats.other_messages++;
    LogMessage("OtherMessageHandler::handle: received other DAQ message, type = %d\n", dme->get_type());
}

bool FinalizePacket::configure(SnortConfig*)
{
    DataBus::subscribe(FINALIZE_PACKET_EVENT, new FinalizePacketHandler(*this));
    DataBus::subscribe(DAQ_OTHER_MSG_EVENT, new OtherMessageHandler());
    return true;
}

void FinalizePacket::show(SnortConfig*)
{
    std::string modify;
    modify += "{ pdu = ";
    modify += std::to_string(modify_pdu);
    modify += ", verdict = ";
    modify += to_string(new_verdict);
    modify += " }";

    ConfigLogger::log_value("start_pdu", start_pdu);
    ConfigLogger::log_value("end_pdu", end_pdu);
    ConfigLogger::log_list("modify", modify.c_str());
    ConfigLogger::log_flag("switch_to_wizard", switch_to_wizard);
    ConfigLogger::log_flag("use_direct_inject", use_direct_inject);
    ConfigLogger::log_flag("defer_whitelist", defer_whitelist);
    ConfigLogger::log_flag("force_whitelist", force_whitelist);
}

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter modify_params[] =
{
    { "pdu", Parameter::PT_INT, "0:max32", "0",
      "Modify verdict in finalize packet for this PDU" },

    { "verdict", Parameter::PT_ENUM,
        "pass | block | replace | whitelist | blacklist | ignore | retry", nullptr,
        "output format for stats" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter fp_params[] =
{
    { "start_pdu", Parameter::PT_INT, "0:max32", "0",
      "Register to receive finalize packet event starting on this PDU" },

    { "end_pdu", Parameter::PT_INT, "0:max32", "0",
      "Deregister for finalize packet events on this PDU" },

    { "modify", Parameter::PT_TABLE, modify_params, nullptr,
      "Modify verdict in finalize event" },

    { "switch_to_wizard", Parameter::PT_BOOL, nullptr, "false",
      "Switch to wizard on first finalize event" },

    { "use_direct_inject", Parameter::PT_BOOL, nullptr, "false",
      "Use ioctl to do payload and reset injects" },

    { "defer_whitelist", Parameter::PT_BOOL, nullptr, "false",
      "Turn on defer whitelist until we switch to wizard" },

    { "force_whitelist", Parameter::PT_BOOL, nullptr, "false",
      "Set ignore direction to both so that flow will be whitelisted" },

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
    uint32_t modify_pdu;
    DAQ_Verdict new_verdict;
    bool switch_to_wizard;
    bool use_direct_inject;
    bool defer_whitelist;
    bool force_whitelist;
};

bool FinalizePacketModule::begin(const char*, int, SnortConfig*)
{
    start_pdu = 0;
    end_pdu = 0;
    modify_pdu = 0;
    new_verdict = MAX_DAQ_VERDICT;
    switch_to_wizard = false;
    use_direct_inject = false;
    defer_whitelist = false;
    force_whitelist = false;
    return true;
}

bool FinalizePacketModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("start_pdu") )
        start_pdu = v.get_uint32();

    else if ( v.is("end_pdu") )
        end_pdu = v.get_uint32();

    else if ( v.is("pdu") )
        modify_pdu = v.get_uint32();

    else if ( v.is("verdict") )
        new_verdict = (DAQ_Verdict)v.get_uint8();

    else if ( v.is("switch_to_wizard") )
        switch_to_wizard = v.get_bool();

    else if ( v.is("use_direct_inject") )
        use_direct_inject = v.get_bool();

    else if ( v.is("defer_whitelist") )
        defer_whitelist = v.get_bool();

    else if ( v.is("force_whitelist") )
        force_whitelist = v.get_bool();

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
    return new FinalizePacket(mod->start_pdu, mod->end_pdu, mod->modify_pdu, mod->new_verdict,
        mod->switch_to_wizard, mod->use_direct_inject, mod->defer_whitelist,
        mod->force_whitelist);
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

