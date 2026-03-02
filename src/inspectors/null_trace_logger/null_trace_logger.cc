//--------------------------------------------------------------------------
// Copyright (C) 2020-2026 Cisco and/or its affiliates. All rights reserved.
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

#include "framework/module.h"
#include "framework/tracer.h"
#include "trace/trace_api.h"

static const char* s_name = "null_trace_logger";
static const char* s_help = "trace logger with a null printout";

using namespace snort;

//-------------------------------------------------------------------------
// Config Parameters
//-------------------------------------------------------------------------

class NullTrace;

class NullTrace : public TraceLoggerPlug
{
public:
    explicit NullTrace() : TraceLoggerPlug(s_name)
    { }

    void log(const char*, const char*, uint8_t, const char*, const Packet*) override
    { }
};

//-------------------------------------------------------------------------
// Module
//-------------------------------------------------------------------------

class NullTraceModule : public Module
{
public:
    NullTraceModule() : Module(s_name, s_help) { }

    Usage get_usage() const override
    { return GLOBAL; }
};

//-------------------------------------------------------------------------
// API
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new NullTraceModule; }

static void mod_dtor(Module* m)
{ delete m; }

static TraceLoggerPlug* trace_ctor(Module*, const std::string&)
{ return new NullTrace; }

static void trace_dtor(TraceLoggerPlug* logger)
{ delete logger; }

static const TraceLogApi trace_api =
{
    {
        PT_TRACE,
        sizeof(TraceLogApi),
        TRACE_LOGAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    TRACER_FLAG__RESERVED,
    trace_ctor,
    trace_dtor
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &trace_api.base,
    nullptr
};

