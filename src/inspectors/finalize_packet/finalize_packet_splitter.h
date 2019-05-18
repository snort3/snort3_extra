//--------------------------------------------------------------------------
// Copyright (C) 2019-2019 Cisco and/or its affiliates. All rights reserved.
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

// finalize_packet_splitter.h author Steve Chew <stechew@cisco.com>

#ifndef FINALIZE_PACKET_SPLITTER_H
#define FINALIZE_PACKET_SPLITTER_H

// Demonstrate how an inspector can subscribe to and receive the
// finalize packet event.

#include "stream/stream_splitter.h"

class FinalizePacketSplitter : public snort::LogSplitter
{
public:
    FinalizePacketSplitter(bool c2s) : LogSplitter(c2s)
    { }

    bool is_paf() override
    {
        return true;
    }

private:
};

#endif
