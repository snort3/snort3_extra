//--------------------------------------------------------------------------
// Copyright (C) 2014-2019 Cisco and/or its affiliates. All rights reserved.
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
// reg_test_splitter.h author davis mcpherson <davmcphe@cisco.com>

#ifndef REG_TEST_SPLITTER_H
#define REG_TEST_SPLITTER_H

#include <stream/stream_splitter.h>

namespace snort
{
class Flow;
struct Packet;
}

//-------------------------------------------------------------------------
// accumulated tcp over maximum splitter (aka footprint)

class RegTestSplitter : public snort::StreamSplitter
{
public:
    RegTestSplitter(bool to_server);

    Status scan(snort::Packet*, const uint8_t*, uint32_t, uint32_t, uint32_t*) override;
    void update() override;
    bool init_partial_flush(snort::Flow*) override;

private:
    void reset();

private:
    uint16_t segs;
    uint16_t bytes;
};

#endif

