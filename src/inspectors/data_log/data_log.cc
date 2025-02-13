//--------------------------------------------------------------------------
// Copyright (C) 2015-2025 Cisco and/or its affiliates. All rights reserved.
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
// data_log.cc author Russ Combs <rcombs@sourcefire.com>

#include <ctime>

#include "flow/flow.h"
#include "framework/data_bus.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "log/text_log.h"
#include "pub_sub/http_events.h"
#include "time/packet_time.h"

using namespace snort;

static const char* s_name = "data_log";
static const char* s_help = "log selected published data to data.log";

static THREAD_LOCAL TextLog* tlog = nullptr;
static THREAD_LOCAL SimpleStats dl_stats;

//-------------------------------------------------------------------------
// data stuff
//-------------------------------------------------------------------------

class LogHandler : public DataHandler
{
public:
    LogHandler(const std::string& s) : DataHandler(s_name), key(s)
    { }

    void handle(DataEvent& e, Flow*) override;

private:
    void log(const uint8_t*, int32_t);
    std::string key;
};

void LogHandler::log(const uint8_t* s, int32_t n)
{
    if ( !s or !*s or n <= 0 )
        return;

    TextLog_Print(tlog, ", ");
    TextLog_Write(tlog, (const char*)s, (unsigned)n);
}

void LogHandler::handle(DataEvent& e, Flow* f)
{
    time_t pt = packet_time();
    struct tm st;
    char buf[26];
    SfIpString ip_str;

    gmtime_r(&pt, &st);
    asctime_r(&st, buf);
    buf[sizeof(buf)-2] = '\0';

    TextLog_Print(tlog, "%s, ", buf);
    TextLog_Print(tlog, "%s, %d, ", f->client_ip.ntop(ip_str), f->client_port);
    TextLog_Print(tlog, "%s, %d", f->server_ip.ntop(ip_str), f->server_port);

    HttpEvent* he = (HttpEvent*)&e;
    int32_t n;
    const uint8_t* s;

    s = he->get_server(n);
    log(s, n);

    s = he->get_authority(n);
    log(s, n);

    s = he->get_uri(n);
    log(s, n);

    n = he->get_response_code();
    if ( n > 0 )
        TextLog_Print(tlog, ", %d", n);

    s = he->get_user_agent(n);
    log(s, n);

    TextLog_NewLine(tlog);
    dl_stats.total_packets++;
}

//-------------------------------------------------------------------------
// inspector stuff
//-------------------------------------------------------------------------

class DataLog : public Inspector
{
public:
    DataLog(const std::string& s, uint64_t n) : key(s), limit(n) { }

    void show(const SnortConfig*) const override;
    void eval(Packet*) override { }

    bool configure(SnortConfig*) override
    {
        unsigned eid = key == "http_request_header_event" ? HttpEventIds::REQUEST_HEADER : HttpEventIds::RESPONSE_HEADER;
        DataBus::subscribe(http_pub_key, eid, new LogHandler(key));
        return true;
    }

    void tinit() override
    { tlog = TextLog_Init(s_name, 64*K_BYTES, limit); }

    void tterm() override
    { TextLog_Term(tlog); }

private:
    std::string key;
    uint64_t limit;
};

void DataLog::show(const SnortConfig*) const
{
    ConfigLogger::log_value("key", key.c_str());
    ConfigLogger::log_value("limit", limit / M_BYTES);
}

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter dl_params[] =
{
    { "key", Parameter::PT_SELECT, "http_request_header_event | http_response_header_event",
      "http_request_header_event ", "name of the event to log" },

    { "limit", Parameter::PT_INT, "0:max32", "0",
      "set maximum size in MB before rollover (0 is unlimited)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class DataLogModule : public Module
{
public:
    DataLogModule() : Module(s_name, s_help, dl_params)
    { }

    const PegInfo* get_pegs() const override
    { return simple_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&dl_stats; }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value& v, SnortConfig*) override;

    Usage get_usage() const override
    { return INSPECT; }

public:
    std::string key;
    uint64_t limit = 0;
};

bool DataLogModule::begin(const char*, int, SnortConfig*)
{
    key.clear();
    limit = 0;
    return true;
}

bool DataLogModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("key") )
        key = v.get_string();

    else if ( v.is("limit") )
        limit = ((uint64_t)v.get_uint32()) * M_BYTES;

    return true;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new DataLogModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* dl_ctor(Module* m)
{
    DataLogModule* mod = (DataLogModule*)m;
    return new DataLog(mod->key, mod->limit);
}

static void dl_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi dl_api
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
    dl_ctor,
    dl_dtor,
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &dl_api.base,
    nullptr
};

