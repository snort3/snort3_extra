//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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
// appid_listener_event_handler.cc author Shravan Rangaraju <shrarang@cisco.com>

#include "appid_listener_event_handler.h"

#include <iomanip>

#include "flow/flow.h"
#include "network_inspectors/appid/appid_api.h"
#include "utils/stats.h"
#include "utils/util.h"

using namespace snort;
using namespace std;

void AppIdListenerEventHandler::handle(DataEvent& event, Flow* flow)
{
    AppidEvent& appid_event = static_cast<AppidEvent&>(event);
    const AppidChangeBits& ac_bits = appid_event.get_change_bitset();

    AppidChangeBits temp_ac_bits = ac_bits;
    temp_ac_bits.reset(APPID_CREATED_BIT);
    if (temp_ac_bits.none())
        return;

    if (!flow)
    {
        if (!config.json_logging)
            WarningMessage("appid_listener: flow is null\n");
        return;
    }

    if (!config.json_logging and !appid_changed(ac_bits))
        return;

    char cli_ip_str[INET6_ADDRSTRLEN], srv_ip_str[INET6_ADDRSTRLEN];
    flow->client_ip.ntop(cli_ip_str, sizeof(cli_ip_str));
    flow->server_ip.ntop(srv_ip_str, sizeof(srv_ip_str));

    if (!config.json_logging and ac_bits.test(APPID_RESET_BIT))
    {
        print_header(cli_ip_str, srv_ip_str, flow->client_port, flow->server_port,
            flow->ip_proto, get_packet_number());

        ostringstream ss(" appid data is reset\n");
        if (!write_to_file(ss.str()))
            LogMessage("%s", ss.str().c_str());

        return;
    }

    const AppIdSessionApi& api = appid_event.get_appid_session_api();
    AppId service = api.get_service_app_id();
    PegCount packet_num = get_packet_number();
    uint32_t httpx_stream_index = 0;
    bool is_httpx = appid_event.get_is_httpx();
    if (is_httpx)
        httpx_stream_index = appid_event.get_httpx_stream_index();

    AppId client = api.get_client_app_id(httpx_stream_index);
    AppId payload = api.get_payload_app_id(httpx_stream_index);
    AppId misc = api.get_misc_app_id(httpx_stream_index);
    AppId referred = api.get_referred_app_id(httpx_stream_index);

    const char *netbios_name = api.get_netbios_name();
    const char *netbios_domain = api.get_netbios_domain();

    if (config.json_logging)
    {
        ostringstream ss;
        JsonStream js(ss);
        print_json_message(js, cli_ip_str, srv_ip_str, *flow, packet_num, api, service,
            client, payload, misc, referred, is_httpx, httpx_stream_index, appid_event.get_packet(),
            netbios_name, netbios_domain);
        if (!write_to_file(ss.str()))
            LogMessage("%s", ss.str().c_str());
    }
    else
        print_message(cli_ip_str, srv_ip_str, *flow, packet_num, service, client,
            payload, misc, referred);
}

void AppIdListenerEventHandler::print_message(const char* cli_ip_str, const char* srv_ip_str,
    const Flow& flow, PegCount packet_num, AppId service, AppId client, AppId payload, AppId misc,
    AppId referred)
{
    print_header(cli_ip_str, srv_ip_str, flow.client_port, flow.server_port, flow.ip_proto,
        packet_num);

    ostringstream ss;
    ss << " service: " << service << " client: " << client << " payload: " <<
        payload << " misc: " << misc << " referred: " << referred << endl;

    if (!write_to_file(ss.str()))
        LogMessage("%s", ss.str().c_str());
}

void AppIdListenerEventHandler::print_json_message(JsonStream& js, const char* cli_ip_str,
    const char* srv_ip_str, const Flow& flow, PegCount packet_num, const AppIdSessionApi& api,
    AppId service, AppId client, AppId payload, AppId misc, AppId referred,
    bool is_httpx, uint32_t httpx_stream_index, const Packet* p, const char* netbios_name,
    const char* netbios_domain)
{
    assert(p);
    char timebuf[TIMEBUF_SIZE];
    ts_print((const struct timeval*)&p->pkth->ts, timebuf, true);
    js.open();
    js.put("session_num", api.get_session_id());
    js.put("pkt_time", timebuf);
    js.put("pkt_num", packet_num);

    const char* service_str = appid_api.get_application_name(service, flow);
    const char* client_str = appid_api.get_application_name(client, flow);
    const char* payload_str = appid_api.get_application_name(payload, flow);
    const char* misc_str = appid_api.get_application_name(misc, flow);
    const char* referred_str = appid_api.get_application_name(referred, flow);
    js.open("apps");
    js.put("service", service_str);
    js.put("client", client_str);
    js.put("payload", payload_str);
    js.put("misc", misc_str);
    js.put("referred", referred_str);
    js.close();

    js.put("proto", get_proto_str(flow.ip_proto));

    js.open("client_info");
    js.put("ip", cli_ip_str);
    js.put("port", flow.client_port);
    js.put("version", api.get_client_info(httpx_stream_index));
    js.close();

    const char* vendor;
    const char* version;
    const AppIdServiceSubtype* subtype;
    api.get_service_info(vendor, version, subtype);
    js.open("service_info");
    js.put("ip", srv_ip_str);
    js.put("port", flow.server_port);
    js.put("version", version);
    js.put("vendor", vendor);
    while (subtype)
    {
        js.open("subtype");
        js.put("service", subtype->service);
        js.put("vendor", subtype->vendor);
        js.put("version", subtype->version);
        js.close();
        subtype = subtype->next;
    }
    js.close();

    bool login_status = false;
    AppId id;
    const char* username = api.get_user_info(id, login_status);
    js.open("user_info");
    js.put("id", id);
    js.put("username", username);
    if (username)
        js.put("login_status", login_status ? "success" : "failure");
    else
        js.put("login_status", "n/a");
    js.close();

    const char* tls_host = api.get_tls_host();
    js.put("tls_host", tls_host);

    const char* dns_host = nullptr;
    if (api.get_dns_session())
        dns_host = api.get_dns_session()->get_host();
    js.put("dns_host", dns_host);

    js.open("netbios_info");
    js.put("netbios_name", netbios_name);
    js.put("netbios_domain", netbios_domain);
    js.close();

    const AppIdHttpSession* hsession = api.get_http_session(httpx_stream_index);
    js.open("http");
    if (!hsession)
    {
        js.put("httpx_stream");
        js.put("host");
        js.put("url");
        js.put("user_agent");
        js.put("response_code");
        js.put("referrer");
    }
    else
    {
        const char* host = hsession->get_cfield(REQ_HOST_FID);
        const char* url = hsession->get_cfield(MISC_URL_FID);
        const char* user_agent = hsession->get_cfield(REQ_AGENT_FID);
        const char* response_code = hsession->get_cfield(MISC_RESP_CODE_FID);
        const char* referrer = hsession->get_cfield(REQ_REFERER_FID);

        if (is_httpx)
            js.put("httpx_stream", to_string(hsession->get_httpx_stream_id()));
        else
            js.put("httpx_stream", nullptr);
        js.put("host", host);
        js.put("url", url);
        js.put("user_agent", user_agent);
        js.put("response_code", response_code);
        js.put("referrer", referrer);
    }

    js.close();
    js.close();
}
