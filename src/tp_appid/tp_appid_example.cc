//--------------------------------------------------------------------------
// Copyright (C) 2016-2023 Cisco and/or its affiliates. All rights reserved.
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

// Brief description:
//
// Minimalist example of an implementation of a third party library for appid
// detection.
// Snort interacts with this library via 3 classes:
// 1) TPLibHandler - to load the third party library.
// 2) ThirdPartyAppIdContext - to initialize and clean-up whatever we might need
// 3) ThirdPartyAppIdSession - for the actual information extracted from packets
// The third party library must provide implementations to the abstract classes
// ThirdPartyAppIdContext and ThirdPartyAppIdSession and must also implement the
// object factory functions returning pointers to the derived classes.
//
//
// Standalone compilation:
// g++ -g -Wall -I/path/to/snort3/src -c tp_appid_example.cc
// g++ -std=c++11 -g -Wall -I/path/to/snort3/src -shared -fPIC -o libtp_appid_example.so tp_appid_example.cc
// As a module (dynamically loaded)  - see CMakeLists.txt

#include <iostream>
#include <sstream>

#include "main/snort_types.h"
#include "network_inspectors/appid/tp_appid_module_api.h"
#include "network_inspectors/appid/tp_appid_session_api.h"
#include "utils/stats.h"

#define WhereMacro __FILE__ << ": " << __FUNCTION__ << ": " << __LINE__

using namespace std;

class ThirdPartyAppIdContextImpl : public ThirdPartyAppIdContext
{
public:
    ThirdPartyAppIdContextImpl(uint32_t ver, const char* mname, ThirdPartyConfig& config)
        : ThirdPartyAppIdContext(ver, mname, config)
    {
        cerr << WhereMacro << endl;
    }

    ~ThirdPartyAppIdContextImpl() override
    {
        cerr << WhereMacro << endl;
    }

    int tinit() override
    {
        stringstream msg;
        msg << WhereMacro << ": per worker thread context initialization." << endl;
        cerr << msg.str();
        return 0;
    }

    bool tfini(bool) override
    {
        stringstream msg;
        msg << WhereMacro << ": per worker-thread context clean-up." << endl;
        cerr << msg.str();
        return false;
    }

    const string& get_user_config() const override { return user_config; }

private:
    string user_config = "";

};

class ThirdPartyAppIdSessionImpl : public ThirdPartyAppIdSession
{
public:

    void reset() override { }
    void delete_with_ctxt() override { delete this; }

    ThirdPartyAppIdSessionImpl(ThirdPartyAppIdContext& tp_ctxt)
        : ThirdPartyAppIdSession(tp_ctxt)
    {
    }

    TPState process(const snort::Packet&, AppidSessionDirection, vector<AppId>&,
        ThirdPartyAppIDAttributeData&) override
    {
        stringstream msg;
        msg  << WhereMacro
             << ": third party packet parsing and appid processing."
             << " Packet: " << snort::get_packet_number() << endl;
        cerr << msg.str();
        return TP_STATE_INIT;
    }

    int disable_flags(uint32_t) override { return 0; }
    TPState get_state() override { return state; }
    void set_state(TPState s) override { state=s; }
    void clear_attr(TPSessionAttr attr) override { flags &= ~attr; }
    void set_attr(TPSessionAttr attr) override { flags |= attr; }
    unsigned get_attr(TPSessionAttr attr) override { return flags & attr; }

private:
    unsigned flags=0;
};

// Object factories to create module and session.
// This is the only way for outside callers to create module and session
// once the .so has been loaded.
extern "C"
{
    SO_PUBLIC ThirdPartyAppIdContextImpl* tp_appid_create_ctxt(ThirdPartyConfig&);
    SO_PUBLIC ThirdPartyAppIdSessionImpl* tp_appid_create_session(ThirdPartyAppIdContext&);
    SO_PUBLIC int tp_appid_pfini();
    SO_PUBLIC int tp_appid_tfini();

    SO_PUBLIC ThirdPartyAppIdContextImpl* tp_appid_create_ctxt(ThirdPartyConfig& cfg)
    {
        return new ThirdPartyAppIdContextImpl(THIRD_PARTY_APPID_API_VERSION,"third party", cfg);
    }

    SO_PUBLIC ThirdPartyAppIdSessionImpl* tp_appid_create_session(ThirdPartyAppIdContext& ctxt)
    {
        return new ThirdPartyAppIdSessionImpl(ctxt);
    }

    SO_PUBLIC int tp_appid_pfini()
    {
        cerr << WhereMacro << ": main thread clean-up." << endl;
        return 0;
    }

    SO_PUBLIC int tp_appid_tfini()
    {
        stringstream msg;
        msg << WhereMacro << ": per worker-thread clean-up." << endl;
        cerr << msg.str();
        return 0;
    }
}
