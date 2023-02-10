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

// domain_filter_test.cc author Russ Combs <rucombs@cisco.com>

#include <string.h>

#include <string>
#include <sstream>

#include "detection/detection_engine.h"
#include "framework/data_bus.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "profiler/memory_profiler_defs.h"
#include "pub_sub/http_events.h"
#include "utils/stats.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;
extern const BaseApi* snort_plugins[];

//--------------------------------------------------------------------------
// clones
//--------------------------------------------------------------------------

Value::~Value()
{
    if ( ss )
        delete ss;
}

void Value::set_first_token()
{
    if ( ss )
        delete ss;

    ss = new std::stringstream(str);
}

bool Value::get_next_token(std::string& tok)
{
    return ss and ( *ss >> tok );
}

//--------------------------------------------------------------------------
// mocks
//--------------------------------------------------------------------------

static DataHandler* s_handler = nullptr;

void DataBus::subscribe(char const*, DataHandler* dh)
{
    s_handler = dh;
}

static const char* s_host = nullptr;

const uint8_t* HttpEvent::get_host(int32_t& len)
{
    len = s_host ? strlen(s_host) : 0;
    return (uint8_t*)s_host;
}

//--------------------------------------------------------------------------
// spies
//--------------------------------------------------------------------------

static unsigned s_alerts = 0;

int DetectionEngine::queue_event(unsigned, unsigned, uint8_t)
{
    ++s_alerts;
    return 0;
}

//--------------------------------------------------------------------------
// stubs
//--------------------------------------------------------------------------

class StreamSplitter* Inspector::get_splitter(bool)
{
    FAIL("get_splitter");
    return nullptr;
}

bool Inspector::likes(Packet*)
{
    FAIL("likes");
    return false;
}

bool Inspector::get_buf(char const*, Packet*, InspectionBuffer&)
{
    FAIL("get_buf");
    return false;
}

Inspector::Inspector() { }
Inspector::~Inspector() { }

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, IndexVec&, const char*, FILE*);

void Module::show_stats() { }
void Module::reset_stats() { }
void Module::show_interval_stats(IndexVec&, FILE*) { }

bool Module::set(char const*, Value&, SnortConfig*) { return false; }
void Module::sum_stats(bool) { }

Module::Module(const char* n, const char* h, const Parameter* p, bool, Trace*)
{ name = n; help = h; params = p; }

MemoryContext::MemoryContext(MemoryTracker&) { }
MemoryContext::~MemoryContext() { }

//--------------------------------------------------------------------------

TEST_GROUP(domain_filter_base)
{
    const BaseApi* api;

    void setup() override
    {
        api = snort_plugins[0];
        CHECK(api != nullptr);
    }
};

TEST(domain_filter_base, base)
{
    CHECK(api->type == PT_INSPECTOR);
    CHECK(api->size == sizeof(InspectApi));

    CHECK(api->name and !strcmp(api->name, "domain_filter"));
    CHECK(api->help);

    CHECK(api->mod_ctor != nullptr);
    CHECK(api->mod_dtor != nullptr);
}

//--------------------------------------------------------------------------

TEST_GROUP(domain_filter_ins)
{
    const InspectApi* api;

    void setup() override
    {
        CHECK(snort_plugins[0] != nullptr);
        CHECK(snort_plugins[0]->type == PT_INSPECTOR);
        api = (InspectApi*)snort_plugins[0];
    }
};

TEST(domain_filter_ins, api)
{
    CHECK(api->type == IT_PASSIVE);
    CHECK(api->proto_bits == 0);

    CHECK(api->ctor != nullptr);
    CHECK(api->dtor != nullptr);
}

TEST(domain_filter_ins, module)
{
    Module* mod = api->base.mod_ctor();
    CHECK(mod != nullptr);

    CHECK(mod->get_name() != nullptr);
    CHECK(mod->get_help() != nullptr);
    CHECK(mod->get_gid() == 175);

    CHECK(mod->get_parameters() != nullptr);
    CHECK(!strcmp(mod->get_parameters()->name, "hosts"));

    CHECK(mod->get_rules() != nullptr);
    CHECK(mod->get_rules()->msg != nullptr);

    CHECK(mod->get_usage() == Module::INSPECT);
    CHECK(mod->get_profile() != nullptr);

    CHECK(mod->get_counts() != nullptr);
    CHECK(mod->get_pegs() != nullptr);

    CHECK(!strcmp(mod->get_pegs()[0].name, "checked"));
    CHECK(!strcmp(mod->get_pegs()[1].name, "filtered"));

    api->base.mod_dtor(mod);
}

TEST(domain_filter_ins, basic)
{
    Module* mod = api->base.mod_ctor();
    CHECK(mod != nullptr);

    Inspector* pi = api->ctor(mod);
    CHECK(pi != nullptr);
    CHECK(s_handler == nullptr);

    api->base.mod_dtor(mod);
    api->dtor(pi);
}

//--------------------------------------------------------------------------

TEST_GROUP(domain_filter_events)
{
    const InspectApi* api;
    Inspector* ins;
    Module* mod;

    void setup() override
    {
        CHECK(snort_plugins[0] != nullptr);
        CHECK(snort_plugins[0]->type == PT_INSPECTOR);
        api = (InspectApi*)snort_plugins[0];

        mod = api->base.mod_ctor();
        CHECK(mod != nullptr);

        Value val("zombie.com\ntest.com apocalypse.com ");
        mod->set("hosts", val, nullptr);
        mod->end(nullptr, 0, nullptr);

        ins = api->ctor(mod);
        CHECK(ins != nullptr);

        CHECK(s_handler != nullptr);

        mod->get_counts()[0] = 0;
        mod->get_counts()[1] = 0;
    }

    void teardown() override
    {
        api->dtor(ins);
        api->base.mod_dtor(mod);
        delete s_handler;
        s_handler = nullptr;
        s_alerts = 0;
    }
};

TEST(domain_filter_events, no_host)
{
    HttpEvent he(nullptr);
    s_host = nullptr;
    s_handler->handle(he, nullptr);
    CHECK(s_alerts == 0);
    CHECK(mod->get_counts()[0] == 0);
    CHECK(mod->get_counts()[1] == 0);
}

TEST(domain_filter_events, no_alert)
{
    HttpEvent he(nullptr);
    s_host = "jest.com";
    s_handler->handle(he, nullptr);
    s_host = "xtest.com";
    s_handler->handle(he, nullptr);
    s_host = "test.co";
    s_handler->handle(he, nullptr);
    CHECK(s_alerts == 0);
    CHECK(mod->get_counts()[0] == 3);
    CHECK(mod->get_counts()[1] == 0);
}

TEST(domain_filter_events, one_alert)
{
    HttpEvent he(nullptr);
    s_host = "test.com";
    s_handler->handle(he, nullptr);
    CHECK(s_alerts == 1);
    CHECK(mod->get_counts()[0] == 1);
    CHECK(mod->get_counts()[1] == 1);
}

TEST(domain_filter_events, mixed_case_alert)
{
    HttpEvent he(nullptr);
    s_host = "TEST.com";
    s_handler->handle(he, nullptr);
    CHECK(s_alerts == 1);
    CHECK(mod->get_counts()[0] == 1);
    CHECK(mod->get_counts()[1] == 1);
}

//--------------------------------------------------------------------------

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

