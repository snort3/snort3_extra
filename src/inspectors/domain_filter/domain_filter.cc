//--------------------------------------------------------------------------
// Copyright (C) 2018-2023 Cisco and/or its affiliates. All rights reserved.
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

// domain_filter.cc author Russ Combs <rucombs@cisco.com>

#include <cassert>
#include <cerrno>

#include <fstream>
#include <string>
#include <unordered_set>
#include <vector>

#include "detection/detection_engine.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "main/thread.h"
#include "profiler/profiler.h"
#include "pub_sub/http_events.h"
#include "utils/util.h"

#define DF_GID 175
#define DF_SID   1

static const char* s_name = "domain_filter";
static const char* s_help = "alert on configured HTTP domains";

using DomainList = std::vector<std::string>;
using DomainSet = std::unordered_set<std::string>;
using namespace snort;

//--------------------------------------------------------------------------
// attributes
//--------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "file", Parameter::PT_STRING, nullptr, nullptr,
      "file with list of domains identifying hosts to be filtered" },

    { "hosts", Parameter::PT_STRING, nullptr, nullptr,
      "list of domains identifying hosts to be filtered" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap s_rules[] =
{
    { DF_SID, "configured domain detected" },

    { 0, nullptr }
};

struct DomainFilterStats
{
    PegCount checked;
    PegCount filtered;
};

static THREAD_LOCAL DomainFilterStats s_counts;

const PegInfo s_pegs[] =
{
    { CountType::SUM, "checked", "domains checked" },
    { CountType::SUM, "filtered", "domains filtered" },

    { CountType::END, nullptr, nullptr }
};

static THREAD_LOCAL ProfileStats s_prof;

//--------------------------------------------------------------------------
// module stuff
//--------------------------------------------------------------------------

class DomainFilterModule : public Module
{
public:
    DomainFilterModule() : Module(s_name, s_help, s_params) { }

    DomainList& get_hosts()
    { return hosts; }

    bool set(const char*, Value&, SnortConfig*) override;

    const PegInfo* get_pegs() const override
    { return s_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&s_counts; }

    unsigned get_gid() const override
    { return DF_GID; }

    const RuleMap* get_rules() const override
    { return s_rules; }

    Usage get_usage() const override
    { return INSPECT; }

    ProfileStats* get_profile() const override
    { return &s_prof; }

public:
    DomainList hosts;
};

bool DomainFilterModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("file") )
    {
        std::ifstream df(v.get_string());

        if ( !df.is_open() )
        {
            ParseError("can't open file %s: %s", v.get_string(), get_error(errno));
            return false;
        }
        std::string tok;

        while ( df >> tok )
            hosts.push_back(tok);
    }
    else if ( v.is("hosts") )
    {
        std::string tok;
        v.set_first_token();

        while ( v.get_next_token(tok) )
            hosts.push_back(tok);
    }
    return true;
}

//--------------------------------------------------------------------------
// event stuff
//--------------------------------------------------------------------------

class HttpHandler : public DataHandler
{
public:
    HttpHandler(DomainSet& sv) : DataHandler(s_name), hosts(sv) { }

    void handle(DataEvent& e, Flow*) override;

private:
    DomainSet& hosts;
};

void HttpHandler::handle(DataEvent& de, Flow*)
{
    Profile profile(s_prof);
    HttpEvent* he = (HttpEvent*)&de;

    int32_t len;
    const char* s = (const char*)he->get_uri_host(len);

    if ( !s or len < 1 )
        return;

    std::string h(s, len);
    transform(h.begin(), h.end(), h.begin(), ::tolower);

    DomainSet::const_iterator it = hosts.find(h);

    if ( it != hosts.end() )
    {
        DetectionEngine::queue_event(DF_GID, DF_SID);
        ++s_counts.filtered;
    }
    ++s_counts.checked;
}

//--------------------------------------------------------------------------
// inspector stuff
//--------------------------------------------------------------------------

class DomainFilter : public Inspector
{
public:
    DomainFilter(DomainList&);

    bool configure(SnortConfig*) override;
    void show(const SnortConfig*) const override;
    void eval(Packet*) override { }

private:
    DomainSet hosts;
};

DomainFilter::DomainFilter(DomainList& sv)
{
    hosts.insert(sv.begin(), sv.end());
    sv.clear();
}

bool DomainFilter::configure(SnortConfig*)
{
    if ( !hosts.empty() )
        DataBus::subscribe(http_pub_key, HttpEventIds::REQUEST_HEADER, new HttpHandler(hosts));

    return true;
}

void DomainFilter::show(const SnortConfig*) const
{
    DomainList domain_list;

    for (const auto& host : hosts)
        domain_list.push_back(host);
    std::sort(domain_list.begin(), domain_list.end());

    std::string sorted_hosts;
    for (const auto& host : domain_list)
    {
        if (!sorted_hosts.empty())
            sorted_hosts += " ";
        sorted_hosts += host;
    }

    if ( sorted_hosts.empty() )
        sorted_hosts = "none";

    ConfigLogger::log_list("hosts", sorted_hosts.c_str());
}

//--------------------------------------------------------------------------
// api stuff
//--------------------------------------------------------------------------

static Module* mod_ctor()
{ return new DomainFilterModule; }

static void mod_dtor(Module* pm)
{ delete pm; }

static Inspector* df_ctor(Module* m)
{
    DomainFilterModule* pm = (DomainFilterModule*)m;
    return new DomainFilter(pm->get_hosts());
}

static void df_dtor(Inspector* p)
{
    assert(p);
    delete p;
}

static const InspectApi df_api =
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

    0,        // proto_bits;
    nullptr,  // buffers
    nullptr,  // service
    nullptr,  // pinit
    nullptr,  // pterm
    nullptr,  // tinit
    nullptr,  // tterm

    df_ctor,
    df_dtor,

    nullptr,  // ssn
    nullptr,  // reset
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &df_api.base,
    nullptr
};

