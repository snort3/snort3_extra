//--------------------------------------------------------------------------
// Copyright (C) 2015-2023 Cisco and/or its affiliates. All rights reserved.
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
// mem_test.cc author Russ Combs <rcombs@sourcefire.com>

#include "flow/flow.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "protocols/packet.h"

using namespace snort;

static const char* s_name = "mem_test";
static const char* s_help = "for testing memory management";

static THREAD_LOCAL SimpleStats mt_stats;

//-------------------------------------------------------------------------
// flow data stuff
//-------------------------------------------------------------------------

class MemTestData : public FlowData
{
public:
    MemTestData(size_t);
    ~MemTestData() override;

    static void init()
    { data_id = FlowData::create_flow_data_id(); }

    void allocate(size_t);
    void deallocate(size_t);

public:
    static unsigned data_id;
    std::vector<char*> data;
    char* base;
    size_t size;
};

unsigned MemTestData::data_id = 0;

MemTestData::MemTestData(size_t n) : FlowData(data_id)
{
    base = new char[n];
    size = n;
}

MemTestData::~MemTestData()
{
    for ( auto* p : data )
        delete[] p;

    delete[] base;
}

void MemTestData::allocate(size_t n)
{
    if ( n < 32 ) n = 32;
    char* p = new char[n];
    snprintf(p, n, "%zu", n);
    data.push_back(p);
}

void MemTestData::deallocate(size_t n)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%zu", n);

    for ( unsigned i = 0; i < data.size(); ++i )
    {
        if ( !data[i] or strcmp(buf, data[i]) )
            continue;

        delete[] data[i];
        data[i] = nullptr;

        assert(size >= n);
        size -= n;

        return;
    }
}

//-------------------------------------------------------------------------
// inspector stuff
//-------------------------------------------------------------------------

class MemTest : public Inspector
{
public:
    MemTest() = default;

    void eval(Packet*) override;

private:
    void begin(Flow*, size_t);
    void end(Flow*);
    void add(Flow*, size_t);
    void sub(Flow*, size_t);
};

// command format is <op><uint>\0
// where <op> is ^, $, +, or - (new, del, add, or sub)

void MemTest::eval(Packet* p)
{
    assert(p->is_udp());

    if ( p->dsize < 3 or p->data[p->dsize - 1] != '\0' )
        return;

    size_t n = (size_t)atoi((const char*)(p->data) + 1);
    
    switch (p->data[0])
    {
    case '^': begin(p->flow, n); break;
    case '$': end(p->flow); break;
    case '+': add(p->flow, n); break;
    case '-': sub(p->flow, n); break;
    default: break;
    }
}

void MemTest::begin(Flow* f, size_t n)
{
    MemTestData* d = new MemTestData(n);
    f->set_flow_data(d);
}

void MemTest::end(Flow* f)
{
    f->free_flow_data(MemTestData::data_id);
}

void MemTest::add(Flow* f, size_t n)
{
    MemTestData* d = (MemTestData*)f->get_flow_data(MemTestData::data_id);
    assert(d);
    d->allocate(n);
}

void MemTest::sub(Flow* f, size_t n)
{
    MemTestData* d = (MemTestData*)f->get_flow_data(MemTestData::data_id);
    assert(d);
    d->deallocate(n);
}

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

class MemTestModule : public Module
{
public:
    MemTestModule() : Module(s_name, s_help)
    { }

    const PegInfo* get_pegs() const override
    { return simple_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&mt_stats; }

    Usage get_usage() const override
    { return INSPECT; }
};

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static void mt_init()
{ MemTestData::init(); }

static Module* mod_ctor()
{ return new MemTestModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* mt_ctor(Module*)
{
    return new MemTest;
}

static void mt_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi mt_api
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
    PROTO_BIT__UDP,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    mt_init, // tinit,
    nullptr, // tterm,
    mt_ctor,
    mt_dtor,
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &mt_api.base,
    nullptr
};

