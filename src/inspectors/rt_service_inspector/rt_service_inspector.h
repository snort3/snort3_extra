//--------------------------------------------------------------------------
// Copyright (C) 2019-2020 Cisco and/or its affiliates. All rights reserved.
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
// rt_service_inspector.h author davis mcpherson <davmcphe@cisco.com>

#ifndef RT_SERVICE_INSPECTOR_H
#define RT_SERVICE_INSPECTOR_H

#include <framework/counts.h>
#include <main/thread.h>

struct RtServiceInspectorStats
{
    PegCount total_packets;
    PegCount flush_requests;
    PegCount hold_requests;
    PegCount search_requests;
    PegCount send_data_requests;
    PegCount send_data_direct_requests;
};

extern THREAD_LOCAL RtServiceInspectorStats rtsi_stats;

#endif

