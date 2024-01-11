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

// string_key.cc author Devendra Dahiphale <ddahipha@cisco.com>
#include <iostream>
#include <random>
#include <algorithm>
#include <string>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <future>
#include <fstream>

#include "common_key.h"

using namespace std;

static long double unordered_total_time;
static long double ordered_total_time;

//TODO: Read these keys from an input file (can be specified as a cmd arg) for a more scalable and generic approach
// all unique keys for evaluating performance against
static vector<string> unique_keys = {"appid-service", "appid-client", "appid-payload", "appid-misc", "appid-referred", "host", "tls-host", "url", "user-agent", "response-code", "referer", "xff", "client-version"}; 

void execute_test(DataUser& sink)
{
    // containers to be compared
    map<string, int> ordered_storage;
    unordered_map<string, int> unordered_storage;

    vector<int> function_ids;
    vector<string> keys;

    auto eng = std::default_random_engine(std::random_device()());

    auto generate_new_key = [&]
    {
        int key_index = rand() % UNIQUE_KEYS_MAX;
        return unique_keys[key_index];
    };

    for (size_t i = 0 ; i < KEYS_MAX ; ++i)
    {
        auto key = generate_new_key();
        keys.push_back(key);

        // 0: lookup operation
        // 1: insert operation
        // 2: clear the container
        if( (i % 100) == 0)
            function_ids.push_back(2);
        else
            function_ids.push_back(rand()%2);
    }

    // shuffle the keys to randomize access order
    shuffle(begin(keys), end(keys), eng);

    auto unordered_operation = [&](auto& key, int &id)
    {
        if(id == 0)
        {
            auto data = unordered_storage.find(key);
            if (data != end(unordered_storage))
            {
                sink.sink(data->second);
            }
        }
        else if(id == 1)
        {
            // does not matter what is the value here
            unordered_storage[key] = 100;
        }
        else if(id == 2)
        {
            unordered_storage.clear();
        }
    };

    auto ordered_operation = [&](auto& key, int &id)
    {
        if(id == 0)
        {
            auto data = ordered_storage.find(key);
            if (data != end(ordered_storage))
            {
                sink.sink(data->second);
            }
        }
        else if(id == 1)
        {
            // does not matter what is the value
            ordered_storage[key] = 100;
        }
        else if(id == 2)
        {
            ordered_storage.clear();
        }
    };

    // spawn threads to time access to unordered map
    auto thread_unordered = async(launch::async,
                                  [&]()
                                  {
                                      return time_test(unordered_operation, function_ids, keys);
                                  });
    auto unordered_time = thread_unordered.get();


    // spawn threads to time access to ordered map
    auto thread_ordered = async(launch::async, [&]
                                {
                                    return time_test(ordered_operation, function_ids, keys);
                                });
    auto ordered_time = thread_ordered.get();


    ordered_total_time += ordered_time.count() * 1.0L / (SCALE_DOWN_FACTOR);
    unordered_total_time += unordered_time.count() * 1.0L / (SCALE_DOWN_FACTOR);
}

int main(int argc, char **argv)
{
    //TODO: output and input files can be sent as command line arguments
    string output_file = "output_";

    // remove "./" from beginning of the program name and append the remaining program name to output file name
    output_file += &argv[0][2];
    output_file += ".txt";
    ofstream output(output_file);
    if (output.fail())
    {
        cout << "Couldn't open output file!" << endl;
        return 1;
    }
    else
    {
        cout << "Check "<< output_file << " for results" << endl;
    }
    output << std::fixed;
    output << std::setprecision(2);

    cout << "Running Tests..." << endl;

    // provide different initial seed to rand() every time you run this program
    srand(time(0));

    // make a dummy sink, so that the optimizer wouldn't know what we are doing after searching into the container
    auto user = make_sink(2);
    long double final_ordered_time = 0, final_unordered_time = 0;

    for(int i = 0; i < TOTAL_TEST_RUNS; i++)
    {
        ordered_total_time = 0; unordered_total_time = 0;

        execute_test(*user);

        final_ordered_time += ordered_total_time / TOTAL_TEST_RUNS;
        final_unordered_time += unordered_total_time / TOTAL_TEST_RUNS;

        output <<"---------------------------------------------------------------------"<<endl;
        output << "Average Time for Ordered Map   : " << setw(10) << (long long)ordered_total_time << " ticks"<<endl;
        output << "Average Time for Unordered Map : " << setw(10) << (long long)unordered_total_time << " ticks"<<endl;
        output <<"---------------------------------------------------------------------"<<endl;
        output << endl << endl;
    }
    output << endl << endl;
    output <<"Key: string" << ". #Test Runs: " << TOTAL_TEST_RUNS << ". Operations: " << KEYS_MAX << ". #Unique Keys: "<<UNIQUE_KEYS_MAX<<endl;
    output <<"*********************************************************************"<<endl;
    output << "Overall Time (scaled down by "<< SCALE_DOWN_FACTOR << "):" << endl;
    output <<"*********************************************************************"<<endl;
    output << "Avg. Time for Ordered Map           : "<< setw(10) << (long long)final_ordered_time<< " ticks"<< endl;
    output << "Avg. Time for Unordered Map         : "<< setw(10) << (long long)final_unordered_time<< " ticks"<<endl<<endl;
    output <<"---------------------------------------------------------------------"<<endl;
    output << "\% Change from Ordered to Unordered : "<< setw(10) << (((final_ordered_time-final_unordered_time)/final_ordered_time) * 100) << endl;
    output <<"*********************************************************************"<<endl;

    output.close();

    return 0;
}
