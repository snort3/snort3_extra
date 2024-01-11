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

// int_key.cc author Devendra Dahiphale <ddahipha@cisco.com>
#include <iostream>
#include <random>
#include <algorithm>
#include <string>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <future>
#include <fstream>
#include <cstring>

#include "common_key.h"

using namespace std;

static long double unordered_total_time;
static long double ordered_total_time;
static long double array_total_time;
static long double vector_total_time;

void execute_test(DataUser& sink)
{
    // containers to be compared
    map<int, int> ordered_storage;
    unordered_map<int, int> unordered_storage;
    int array_storage[UNIQUE_KEYS_MAX] = {0};
    vector<int> vector_storage(UNIQUE_KEYS_MAX, 0);

    vector<int> function_ids;
    // a vector of all keys to be tested, which we can shuffle in order to randomize input
    vector<int> keys;

    // for uniform probability distribution
    auto eng = std::default_random_engine(std::random_device()());

    auto generate_new_key = [&]
    {
        int key = rand() % UNIQUE_KEYS_MAX;
        return key;
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
            unordered_storage[key] = key;
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
            ordered_storage[key] = key;
        }
        else if(id == 2)
        {
            ordered_storage.clear();
        }
    };
    
    auto array_operation = [&](auto& key, int &id)
    {
        if(id == 0)
        {
            auto data = array_storage[key];
            sink.sink(data);
        }
        else if(id == 1)
        {
            array_storage[key] = key;
        }
        else if(id == 2)
        {
            memset(array_storage, 0, UNIQUE_KEYS_MAX);
        }
    };

    auto vector_operation = [&](auto& key, int &id)
    {
        if(id == 0)
        {
            auto data = vector_storage[key];
            sink.sink(data);
        }
        else if(id == 1)
        {
            vector_storage[key] = key;
        }
        else if(id == 2)
        {
            vector_storage.clear();
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


    // spawn threads to time access to array
    auto thread_array = async(launch::async, [&]
                                {
                                    return time_test(array_operation, function_ids, keys);
                                });
    auto array_time = thread_array.get();


    // spawn threads to time access to vector
    auto thread_vector = async(launch::async, [&]
                                {
                                    return time_test(vector_operation, function_ids, keys);
                                });
    auto vector_time = thread_vector.get();


    ordered_total_time += ordered_time.count() * 1.0L/ (SCALE_DOWN_FACTOR);
    unordered_total_time += unordered_time.count() * 1.0L/ (SCALE_DOWN_FACTOR);
    array_total_time += array_time.count() * 1.0L/ (SCALE_DOWN_FACTOR);
    vector_total_time += vector_time.count() * 1.0L/ (SCALE_DOWN_FACTOR);
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
        cout << "Couldn't open output file! : " << output_file << endl;
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

    // To hide from optimizing container accesses
    auto user = make_sink(2);
    long double final_ordered_time = 0, final_unordered_time = 0, final_array_time = 0, final_vector_time = 0;

    for(int i = 0; i < TOTAL_TEST_RUNS; i++)
    {
        // reset vars used for a test
        ordered_total_time = 0; unordered_total_time = 0; array_total_time = 0; vector_total_time = 0;

        execute_test(*user);

        final_ordered_time += ordered_total_time / TOTAL_TEST_RUNS;
        final_unordered_time += unordered_total_time / TOTAL_TEST_RUNS;
        final_array_time += array_total_time / TOTAL_TEST_RUNS;
        final_vector_time += vector_total_time / TOTAL_TEST_RUNS;

        output <<"---------------------------------------------------------------------"<<endl;
        output << "Average Time for Ordered Map   : " << setw(10) << (long long)ordered_total_time << " ticks"<< endl;
        output << "Average Time for Unordered Map : " << setw(10) << (long long)unordered_total_time << " ticks"<<endl;
        output << "Average Time for Array         : " << setw(10) << (long long)array_total_time << " ticks"<<endl;
        output << "Average Time for Vector        : " << setw(10) << (long long)vector_total_time << " ticks"<<endl;
        output <<"---------------------------------------------------------------------"<<endl;
        output << endl << endl;
    }
    output << endl << endl;
    output <<"Key: int" << ". #Test Runs: " << TOTAL_TEST_RUNS << ". Operations: " << KEYS_MAX << ". #Unique Keys: "<<UNIQUE_KEYS_MAX<<endl;
    output <<"*********************************************************************"<<endl;
    output << "Overall Time (scaled down by "<< SCALE_DOWN_FACTOR << "):" << endl;
    output <<"*********************************************************************"<<endl;
    output << "Avg. Time for Ordered Map       : "<< setw(10)<< (long long)(final_ordered_time) << " ticks"<< endl;
    output << "Avg. Time for Unordered Map     : "<< setw(10)<< (long long)(final_unordered_time) << " ticks"<< endl;
    output << "Avg. Time for Array             : "<< setw(10)<< (long long)(final_array_time) << " ticks"<<endl;
    output << "Avg. Time for Vector            : "<< setw(10)<< (long long)(final_vector_time) << " ticks"<<endl << endl;
    output <<"---------------------------------------------------------------------"<<endl;
    output << "\% Change Ordered to Unordered  : "<< setw(10)<< (((final_ordered_time-final_unordered_time)/final_ordered_time) * 100) << endl;
    output << "\% Change Ordered to Array      : "<< setw(10)<< (((final_ordered_time-final_array_time)/final_ordered_time) * 100) << endl;
    output << "\% Change Ordered to Vector     : "<< setw(10)<< (((final_ordered_time-final_vector_time)/final_ordered_time) * 100) << endl;
    output << "\% Change Unordered to Array    : "<< setw(10)<< (((final_unordered_time-final_array_time)/final_unordered_time) * 100) << endl;
    output << "\% Change Unordered to Vector   : "<< setw(10)<< (((final_unordered_time-final_vector_time)/final_unordered_time) * 100) << endl;
    output << "\% Change Array to Vector       : "<< setw(10)<< (((final_array_time-final_vector_time)/final_array_time) * 100) << endl;
    output <<"*********************************************************************"<<endl;

    output.close();

    return 0;
}
