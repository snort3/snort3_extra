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
// appid_listener.h author Shravan Rangaraju <shrarang@cisco.com>

#ifndef APPID_LISTENER_H
#define APPID_LISTENER_H

#include <fstream>
#include <mutex>
#include <string>

#define MOD_NAME "appid_listener"

struct AppIdListenerConfig
{
    bool json_logging = false;
    std::string file_name;
    std::ofstream file_stream;
    std::mutex file_mutex;
};

#endif
