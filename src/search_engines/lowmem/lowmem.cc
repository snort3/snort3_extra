//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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

/*
*   An abstracted interface to the Multi-Pattern Matching routines,
*   thats why we're passing 'void *' objects around.
*
*   Marc A Norton <mnorton@sourcefire.com>
*
*   Updates:
*   3/06 - Added AC_BNFA search
*/
// lowmem.cc author Russ Combs <rucombs@cisco.com>

#include "log/messages.h"
#include "framework/module.h"
#include "framework/mpse.h"
#include "main/snort_types.h"
#include "profiler/profiler.h"

#include "sfksearch.h"

using namespace snort;

#define MOD_NAME "lowmem"
#define MOD_HELP "Keyword Trie (low memory, low performance) MPSE"

struct BnfaCounts
{
    PegCount searches;
    PegCount matches;
    PegCount bytes;
};

static THREAD_LOCAL BnfaCounts lm_counts;
static THREAD_LOCAL ProfileStats lm_stats;

const PegInfo lm_pegs[] =
{
    { CountType::SUM, "searches", "number of search attempts" },
    { CountType::SUM, "matches", "number of times a match was found" },
    { CountType::SUM, "bytes", "total bytes searched" },

    { CountType::END, nullptr, nullptr }
};

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

class LowmemModule : public Module
{
public:
    LowmemModule() : Module(MOD_NAME, MOD_HELP) { }

    ProfileStats* get_profile() const override
    { return &lm_stats; }

    const PegInfo* get_pegs() const override
    { return lm_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&lm_counts; }

    Usage get_usage() const override
    { return GLOBAL; }
};

//-------------------------------------------------------------------------
// mpse
//-------------------------------------------------------------------------

class LowmemMpse : public Mpse
{
private:
    KTRIE_STRUCT* obj;

public:
    LowmemMpse(const MpseAgent* agent) : Mpse("lowmem")
    { obj = KTrieNew(0, agent); }

    ~LowmemMpse() override
    { KTrieDelete(obj); }

    int add_pattern(const uint8_t* P, unsigned m, const PatternDescriptor& desc, void* user) override
    { return KTrieAddPattern(obj, P, m, desc.no_case, desc.negated, user); }

    int prep_patterns(SnortConfig* sc) override
    { return KTrieCompile(sc, obj); }

    int get_pattern_count() const override
    { return KTriePatternCount(obj); }

    int search(const uint8_t*, int, MpseMatch, void*, int*) override;
};

int LowmemMpse::search(const uint8_t* T, int n, MpseMatch match, void* context, int* current_state)
{
    Profile profile(lm_stats);  // cppcheck-suppress unreadVariable

    lm_counts.searches++;
    lm_counts.bytes += n;

    *current_state = 0;
    int found =  KTrieSearch(obj, T, n, match, context);

    lm_counts.matches += found;
    return found;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new LowmemModule;
}

static void mod_dtor(Module* p)
{
    delete p;
}

static Mpse* lm_ctor(const SnortConfig*, class Module*, const MpseAgent* agent)
{
    return new LowmemMpse(agent);
}

static void lm_dtor(Mpse* p)
{
    delete p;
}

static void lm_init()
{
    KTrie_init_xlatcase();
    KTrieInitMemUsed();
}

static void lm_print()
{
    if ( !KTrieMemUsed() )
        return;

    double x = (double)KTrieMemUsed();

    LogMessage("[ LowMem Search-Method Memory Used : %g %s ]\n",
        (x > 1.e+6) ?  x/1.e+6 : x/1.e+3,
        (x > 1.e+6) ? "MBytes" : "KBytes");
}

static const MpseApi lm_api =
{
    {
        PT_SEARCH_ENGINE,
        sizeof(MpseApi),
        SEAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        MOD_NAME,
        MOD_HELP,
        mod_ctor,
        mod_dtor
    },
    MPSE_BASE,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    lm_ctor,
    lm_dtor,
    lm_init,
    lm_print,
    nullptr
};

SO_PUBLIC const snort::BaseApi* snort_plugins[] =
{
    &lm_api.base,
    nullptr
};

