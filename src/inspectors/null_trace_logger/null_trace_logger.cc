//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
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
// null_trace_logger.cc author Oleksandr Serhiienko <oserhiie@cisco.com>
//                      author Oleksii Shumeiko <oshumeik@cisco.com>

#include "framework/decode_data.h"  // for PROTO_BIT__NONE
#include "framework/inspector.h"
#include "framework/module.h"
#include "trace/trace_api.h"
#include "trace/trace_logger.h"

static const char* s_name = "null_trace_logger";
static const char* s_help = "trace logger with a null printout";

using namespace snort;

//-------------------------------------------------------------------------
// logger
//-------------------------------------------------------------------------

class NullTraceLogger : public TraceLogger
{
public:
    void log(const char*, const char*, uint8_t, const char*, const Packet*) override
    { }
};

//-------------------------------------------------------------------------
// logger factory
//-------------------------------------------------------------------------

class NullLoggerFactory : public TraceLoggerFactory
{
public:
    NullLoggerFactory() = default;
    NullLoggerFactory(const NullLoggerFactory&) = delete;
    NullLoggerFactory& operator=(const NullLoggerFactory&) = delete;

    TraceLogger* instantiate() override
    { return new NullTraceLogger(); }
};

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

class NullLoggerModule : public Module
{
public:
    NullLoggerModule() : Module(s_name, s_help) { }

    Usage get_usage() const override
    { return GLOBAL; }
};

//-------------------------------------------------------------------------
// inspector
//-------------------------------------------------------------------------

class NullLoggerInspector : public Inspector
{
public:
    void eval(Packet*) override { }
    bool configure(SnortConfig* sc) override
    { return TraceApi::override_logger_factory(sc, new NullLoggerFactory()); }
};

//-------------------------------------------------------------------------
// API
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new NullLoggerModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* ntl_ctor(Module*)
{ return new NullLoggerInspector; }

static void ntl_dtor(Inspector* p)
{ delete p; }

static const InspectApi ntl_api
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
    ntl_ctor,
    ntl_dtor,
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &ntl_api.base,
    nullptr
};

