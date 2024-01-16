2024-01-16: 3.1.78.0

* copyright: update year to 2024

2023-11-07: 3.1.74.0

* codecs, daqs, inspectors, ips_options, loggers: fix cppcheck issues

2023-02-22: 3.1.56.0

* copyright: update for year 2023

2022-12-20: 3.1.50.0

* appid, data_log, cpeos, domain_filter: convert to use Snort's new PubKey

2022-11-17: 3.1.47.0

* appid: do not write out finished events

2022-09-22: 3.1.42.0

* appid_listener: made the listener http(2,3) version agnostic

2022-08-25 3.1.40.0

* changeLog: change to md format

2022-06-30: 3.1.33.0

* dpx: update includes for trace API

2022-01-25: 3.1.21.0

* copyright: Update year to 2022

2021-12-01: 3.1.18.0

* appid_listener: subscribe to the network data bus
* build: remove config.h includes since not present
* build: remove unreachable code
* dpx: replace Value::get_long() with a platform-independent type
* memory: remove explicit allocation tracking

2021-11-17: 3.1.17.0

* rna: inspector to validate publishing rna cpe os event

2021-08-11: 3.1.10.0

* build: install DAQ modules and Snort plugins in separate folders

2021-06-16: 3.1.6.0

* domain_filter: use uri-host instead of authority
* inspectors: update HttpEvent:get_host() to get_authority()

2021-03-27: 3.1.3.0

* appid_listener: Log netbios_name and netbios_domain in json output
* daq_socket: Update for the removal of the RETRY DAQ verdict
* inspectors: Remove Actions::type

2021-03-11: 3.1.2.0

* cd_pbb: Fix format string warning for ethertype
* mem_test: Modernize constructor declaration

2021-01-13: 3.1.0.0

* appid: Update third party implementation for modified tfini()

2020-12-20: 3.0.3 build 6

* appid: Update third party implementation for added get_user_config()

2020-11-16: 3.0.3 build 5

* appid: Log user information in listener output

2020-10-07: 3.0.3 build 2

* appid: Update for third party API changes
* dpx: Add traces for dpx module

2020-09-23: 3.0.3 build 1

* appid_listener: Support writing appid data to file
* appid_listener: Update function header for third party reset
* cmake: Support cmake build type configuration

2020-09-13: 3.0.2 build 6

* appid_listener: Support json logging

2020-07-28: 3.0.2 build 3

* inspectors: Add null_trace_logger passive inspector

2020-07-15: 3.0.2 build 2

* domain_filter: Sort host list in verbose startup output

2020-07-06: 3.0.2 build 1

* appid: Include appid session api in appid event
* appid: Update third party context member functions to prune connections during reload
* data_log: Fix 32-bit build
* src: Remove plugins only used for regression testing

2020-06-18: 3.0.1 build 5

* appid: Fix warning
* appid: Update snort3_extra to allow appid_listener in tests
* rt_global: Add the option to populate drop reason ID mappings

2020-05-20: 3.0.1 build 4

* codecs: Inherit codec modules from BaseCodecModule class.
* ftp_data: Fix race condition
* mpse: Constify snort config args
* rt_service: The reg test service inspector splitter is a paf splitter so return true from is_paf()
* snort_config: Constify Inspector::show and remove unnecessary logger args

2020-04-23: 3.0.1 build 2

* inspectors: Update verbose config output in show() method to a new format
* rt_global: Add support for fallback to avc_only processing

2020-03-31: 3.0.1 build 1

* rt_service_inspector: Handle detained inspection event.

2020-03-25: build 270

* build: Bump the C++ compiler supported feature set requirement to C++14
* rt_service_inspector: Add ability to test send_data using DAQ injects and ioctls
* rt_service_inspector: Hold packet via Active rather than Stream

2020-03-12: build 269

* daq_socket: Include unistd.h rather than sys/unistd.h for better portability
* finalize_packet: Allow configuration of the direct inject feature.
* finalize_packet: Can force a whitelist verdict and use deferred whitelist feature

2020-02-21: 3.0.0 build 268

* appid: Cleanup terminology
* appid: Get rid of ENABLE_APPID_THIRD_PARTY flag
* appid: Rename third-party appid test library
* appid: Support third party reload when snort is running with single packet thread
* appid: Use 3rd party api version that tp_appid_example gets compiled against
* copyright: Update year to 2020
* inspectors: Remove printing module name in inspectors ::show() method

2019-11-22: build 265

* rt_global_inspector: Updates to build with latest changes to ReloadResourceTuner base class

2019-11-06: build 264

* inspectors: Update reg test global inspectors to match changes in reload resource tuner api

2019-10-09: build 262

* finalize_packet: Convert to using DAQ_OTHER_MSG_EVENT
* finalize_packet: Verify that pkth is available in finalize event handler.
* regtest: Add other_message test option and event handler
* rt_global: Add changes to test global level service inspectors

2019-09-12: build 261

* finalize_packet: Restart appid detection on next packet.
* rt_packet: Add option to retry all packets and switch to liking IP packets

2019-08-28: build 260

* binder: Add test code for testing switch to wizard
* reload: Update reload logic per PR review comments

2019-08-21: build 259

* build: Fix miscellaneous cppcheck warnings
* domain_filter: Fix cppcheck warnings in unit tests
* finalize_packet: Add param to change the verdict on an event
* rt_service: Add test code to exercise no_ack APIs
* rt_service_inspector: Added a reload framework support
* rt_service_inspector: Add help string to memcap param

2019-07-17: build 258

* daq_regtest: Add ignore_vlan option
* daq_socket: Fix warnings

2019-06-19: build 257

* finalize_packet: Add inspector to test the handling of the finalize.packet event.
* reg_test_inspectors: Split reg test inspector into a service inspector and a packet inspector
* reg_test: Updates to test accelerated blocking
* spelling: Appease the spell checker

2019-05-22: build 256

* DAQng: Remove dependency on sfbpf_dlt.h
* daqs: Port RegTest DAQ module to DAQng
* daqs: Port Socket DAQ module to DAQng
* flow: An emulator for comparing map, unordered map, array and vector for string and integer keys types

2019-05-03: build 255

* test: Remove cruft

2019-04-10: build 252

* offload: Framework changes to support polling for completed batch searches
* so_rules: Fix comments

2019-03-31: build 251

* alert_ex: Fix parameters
* copyright: Update year to 2019
* daq_regtest: Adding retry_delay option to allow timstamp changes in retry and subsequent packets
* lowmem: Fixed constness of get_pattern_count
* memory: Add size_of to various FlowData subclasses
* mem_test: Initial support for memory testing

2018-12-06: build 250

* build: Fix some unused parameter warnings
* data_log: Update limit range
* inspectors: Use updated databus to handle module reload
* reg_test: Updated to work with active api

2018-11-07: build 249

* appid: Code refactoring - returning third party state from process call
* tp_appid: Fixed mock lib cmake error

