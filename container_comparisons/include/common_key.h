//--------------------------------------------------------------------------
// Copyright (C) 2019-2024 Cisco and/or its affiliates. All rights reserved.
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

// common_key.h author Devendra Dahiphale <ddahipha@cisco.com>
#ifndef COMMON_KEY_H
#define COMMON_KEY_H

#include <iostream>
#include <iomanip>
#include <vector>
#include <chrono>
#include <stdexcept>
#include <sstream>

using namespace std;

#define UNIQUE_KEYS_MAX  13

// the number of keys we will generate (the size of the test)
// 10 million cumulative operations on each container for every test
#define KEYS_MAX 10000000

#define TOTAL_TEST_RUNS 100

// For avoiding overflow for multiple run of the test
#define SCALE_DOWN_FACTOR 10000

template<class F, class KEY_TYPE>
auto time_test(F&& f, vector<int> function_ids, const vector<KEY_TYPE> keys)
{
    int index = 0;
    auto start_time = chrono::system_clock::now();

    for (auto const& key : keys)
    {
        f(key, function_ids[index]);
        index++;
    }

    auto stop_time = chrono::system_clock::now();
    auto diff =  stop_time - start_time;
    return diff;
}

struct ReportKey
{
    size_t total_keys;
    int miss_chance;
};

std::ostream& operator<<(std::ostream& os, const ReportKey& key)
{
    return os << "miss=" << setw(4) << key.miss_chance << "%";
}


// use a virtual method to prevent the optimizer from detecting that our sink function actually does nothing. otherwise it might skew the test
struct DataUser
{
    virtual void sink(const int &) = 0;
    virtual ~DataUser() = default;
};

struct RealDataUser : DataUser
{
    virtual void sink(const int &) override
    {
    }
};

struct RealDataUserPrint : DataUser
{
    virtual void sink(const int &data) override
    {
        cout << data << endl;
    }
};

// this is a runtime operation and therefore prevents the optimizer from realizing that the sink does nothing
std::unique_ptr<DataUser> make_sink(const int &id)
{
    if (id == 1)
        return make_unique<RealDataUserPrint>();
    if (id == 2)
        return make_unique<RealDataUser>();
    throw logic_error("wrong sink type");
}
#endif
