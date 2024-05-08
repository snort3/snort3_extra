//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

// ips_pkt_num.cc author Russ Combs <rucombs@cisco.com>

#include "framework/decode_data.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "framework/pig_pen.h"
#include "framework/range.h"
#include "hash/hash_key_operations.h"
#include "profiler/profiler.h"

using namespace snort;

static const char* s_name = "pkt_num";
static const char* s_help = "alert on raw packet number";

static THREAD_LOCAL ProfileStats pkt_num_perf_stats;

//-------------------------------------------------------------------------
// option
//-------------------------------------------------------------------------

class PktNumOption : public IpsOption
{
public:
    PktNumOption(const RangeCheck& c) : IpsOption(s_name), config(c)
    { }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

private:
    RangeCheck config;
};

uint32_t PktNumOption::hash() const
{
    uint32_t a, b, c;

    a = config.op;
    b = config.min;
    c = config.max;

    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    return c;
}

bool PktNumOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(s_name, ips.get_name()) )
        return false;

    const PktNumOption& rhs = (const PktNumOption&)ips;
    return ( config == rhs.config );
}

IpsOption::EvalStatus PktNumOption::eval(Cursor&, Packet*)
{
    Profile profile(pkt_num_perf_stats);    // cppcheck-suppress unreadVariable

    if ( config.eval(PigPen::get_packet_number()) )
        return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

#define RANGE "1:"

static const Parameter s_params[] =
{
    { "~range", Parameter::PT_INTERVAL, RANGE, nullptr,
      "check if packet number is in given range" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class PktNumModule : public Module
{
public:
    PktNumModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &pkt_num_perf_stats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    RangeCheck data;
};

bool PktNumModule::begin(const char*, int, SnortConfig*)
{
    data.init();
    return true;
}

bool PktNumModule::set(const char*, Value& v, SnortConfig*)
{
    assert(v.is("~range"));
    return data.validate(v.get_string(), RANGE);
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new PktNumModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* pkt_num_ctor(Module* p, IpsInfo&)
{
    PktNumModule* m = (PktNumModule*)p;
    return new PktNumOption(m->data);
}

static void pkt_num_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi pkt_num_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    1, PROTO_BIT__TCP,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    pkt_num_ctor,
    pkt_num_dtor,
    nullptr
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &pkt_num_api.base,
    nullptr
};

