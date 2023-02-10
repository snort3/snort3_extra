/*--------------------------------------------------------------------------
// Copyright (C) 2015-2023 Cisco and/or its affiliates. All rights reserved.
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
*/
// daq_socket.c authors Russ Combs <rucombs@cisco.com> and Carter Waxman <cwaxman@cisco.com>

#include <errno.h>
#include <netinet/in.h>
// putting types.h here because of Bug in FreeBSD
#include <sys/types.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <daq_module_api.h>
#include <daq_dlt.h>

#include <daq/daq_user.h>

#define DAQ_MOD_VERSION 1
#define DAQ_NAME "socket"
#define DAQ_TYPE (DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_MULTI_INSTANCE)
#define DEFAULT_PORT 8000
#define DEFAULT_POOL_SIZE 16

// FIXIT-M this should be defined by daq_module_api.h
#define SET_ERROR(mod_inst, ...) daq_base_api.set_errbuf(mod_inst, __VA_ARGS__)

typedef struct _SocketMsgDesc
{
    DAQ_Msg_t msg;
    DAQ_PktHdr_t pkt_hdr;
    DAQ_UsrHdr_t pci;
    struct _SocketMsgDesc* next;
} SocketMsgDesc;

typedef struct
{
    SocketMsgDesc* pool;
    SocketMsgDesc* free_list;
    DAQ_MsgPoolInfo_t info;
} SocketMsgPool;

typedef struct
{
    DAQ_ModuleInstance_h mod_inst;

    struct sockaddr_in sin_a;
    struct sockaddr_in sin_b;

    DAQ_Stats_t stats;

    SocketMsgPool pool;

    int sock_a;  // recv from b
    int sock_b;  // recv from a
    int sock_c;  // connect

    int use_a;
    int port;
    int passive;

    unsigned timeout;
    unsigned snaplen;

    uint8_t ip_proto;

    volatile bool interrupted;
} SocketContext;

static DAQ_BaseAPI_t daq_base_api;

static DAQ_VariableDesc_t socket_variable_descriptions[] =
{
    { "port", "Port number to use for connecting to socket", DAQ_VAR_DESC_REQUIRES_ARGUMENT },
    { "proto", "Transport protocol to use for connecting to socket", DAQ_VAR_DESC_REQUIRES_ARGUMENT },
};

static int create_message_pool(SocketContext* sc, unsigned size)
{
    SocketMsgPool* pool = &sc->pool;
    pool->pool = calloc(sizeof(SocketMsgDesc), size);
    if (!pool->pool)
    {
        SET_ERROR(sc->mod_inst, "%s: Could not allocate %zu bytes for a packet descriptor pool!",
                __func__, sizeof(SocketMsgDesc) * size);
        return DAQ_ERROR_NOMEM;
    }
    pool->info.mem_size = sizeof(SocketMsgDesc) * size;
    pool->free_list = NULL;
    while (pool->info.size < size)
    {
        /* Allocate packet data and set up descriptor */
        SocketMsgDesc* desc = &pool->pool[pool->info.size];
        desc->msg.data = malloc(sc->snaplen);
        if (!desc->msg.data)
        {
            SET_ERROR(sc->mod_inst, "%s: Could not allocate %d bytes for a packet descriptor message buffer!",
                    __func__, sc->snaplen);
            return DAQ_ERROR_NOMEM;
        }
        pool->info.mem_size += sc->snaplen;
        desc->pci.ip_proto = sc->ip_proto;

        /* Initialize non-zero invariant packet header fields. */
        DAQ_PktHdr_t* pkt_hdr = &desc->pkt_hdr;
        pkt_hdr->address_space_id = 0;
        pkt_hdr->ingress_index = DAQ_PKTHDR_UNKNOWN;
        pkt_hdr->ingress_group = DAQ_PKTHDR_UNKNOWN;
        pkt_hdr->egress_index = DAQ_PKTHDR_UNKNOWN;
        pkt_hdr->egress_group = DAQ_PKTHDR_UNKNOWN;
        pkt_hdr->flags = 0;
        pkt_hdr->opaque = 0;

        /* Initialize non-zero invariant message header fields. */
        DAQ_Msg_t* msg = &desc->msg;
        msg->priv = desc;
        msg->type = DAQ_MSG_TYPE_PACKET;
        msg->hdr_len = sizeof(*pkt_hdr);
        msg->hdr = pkt_hdr;

        /* Place it on the free list */
        desc->next = pool->free_list;
        pool->free_list = desc;

        pool->info.size++;
    }
    pool->info.available = pool->info.size;
    return DAQ_SUCCESS;
}

//-------------------------------------------------------------------------
// socket functions
//-------------------------------------------------------------------------

static int sock_setup(SocketContext* socket_context)
{
    struct sockaddr_in sin;

    if ((socket_context->sock_c = socket(PF_INET, SOCK_STREAM, 0)) == -1)
    {
        char error_msg[1024] = {0};
        strerror_r(errno, error_msg, sizeof(error_msg));
        SET_ERROR(socket_context->mod_inst, "%s: can't create listener socket (%s)\n", __func__, error_msg);
        return -1;
    }

    sin.sin_family = PF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(socket_context->port);

    if (bind(socket_context->sock_c, (struct sockaddr*)&sin, sizeof(sin)) == -1)
    {
        char error_msg[1024] = {0};
        strerror_r(errno, error_msg, sizeof(error_msg));
        SET_ERROR(socket_context->mod_inst, "%s: can't bind listener socket (%s)\n", __func__, error_msg);
        return -1;
    }

    if (listen(socket_context->sock_c, 2) == -1)
    {
        char error_msg[1024] = {0};
        strerror_r(errno, error_msg, sizeof(error_msg));
        SET_ERROR(socket_context->mod_inst, "%s: can't listen on socket (%s)\n", __func__, error_msg);
        return -1;
    }
    return 0;
}

static void sock_cleanup(SocketContext* socket_context)
{
    if (socket_context->sock_c >= 0)
        close(socket_context->sock_c);

    if (socket_context->sock_a >= 0)
        close(socket_context->sock_a);

    if (socket_context->sock_b >= 0)
        close(socket_context->sock_b);

    socket_context->sock_c = socket_context->sock_a = socket_context->sock_b = -1;
}

static int sock_recv(SocketContext* socket_context, SocketMsgDesc* desc, int* sock)
{
    int n = recv(*sock, desc->msg.data, socket_context->snaplen, 0);

    if (n <= 0)
    {
        if (errno != EINTR)
        {
            char error_msg[1024] = {0};
            strerror_r(errno, error_msg, sizeof(error_msg));
            SET_ERROR(socket_context->mod_inst, "%s: can't recv from socket (%s)\n", __func__, error_msg);
            desc->pci.flags = DAQ_USR_FLAG_END_FLOW;
            *sock = -1;
        }
        return 0;
    }
    return n;
}

static int sock_send(SocketContext* socket_context, int sock, const uint8_t* buf, uint32_t len)
{
    if (sock < 0)
        return 0;

    int n = send(sock, buf, len, 0);

    while (0 <= n && (uint32_t)n < len)
    {
        buf += n;
        len -= n;
        n = send(sock, buf, len, 0);
    }
    if (n == -1)
    {
        char error_msg[1024] = {0};
        strerror_r(errno, error_msg, sizeof(error_msg));
        SET_ERROR(socket_context->mod_inst, "%s: can't send on socket (%s)\n", __func__, error_msg);
        return -1;
    }
    return 0;
}

static int sock_accept(SocketContext* socket_context, SocketMsgDesc* desc, int* sock, struct sockaddr_in* psin)
{
    const char* banner;
    socklen_t len = sizeof(*psin);
    *sock = accept(socket_context->sock_c, (struct sockaddr*)psin, &len);

    if (*sock == -1)
    {
        char error_msg[1024] = {0};
        strerror_r(errno, error_msg, sizeof(error_msg));
        SET_ERROR(socket_context->mod_inst, "%s: can't accept incoming connection (%s)\n", __func__, error_msg);
        return -1;
    }
    banner = socket_context->use_a ? "client\n" : "server\n";
    sock_send(socket_context, *sock, (const uint8_t*)banner, 7);

    desc->pci.flags = DAQ_USR_FLAG_START_FLOW;
    return 0;
}

static int sock_poll(SocketContext* socket_context, SocketMsgDesc* desc, int* sock, struct sockaddr_in* psin)
{
    int max_fd;
    fd_set inputs;

    if (socket_context->sock_c < 0)
        return 0;

    FD_ZERO(&inputs);
    FD_SET(socket_context->sock_c, &inputs);
    max_fd = socket_context->sock_c;

    if (*sock > 0)
    {
        FD_SET(*sock, &inputs);

        if (*sock > max_fd)
            max_fd = *sock;
    }

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    if (!select(max_fd+1, &inputs, NULL, NULL, &timeout))
        return 0;

    else if (*sock >= 0 && FD_ISSET(*sock, &inputs))
        return sock_recv(socket_context, desc, sock);

    else if (*sock < 0 && FD_ISSET(socket_context->sock_c, &inputs))
        return sock_accept(socket_context, desc, sock, psin);

    return 0;
}

//-------------------------------------------------------------------------
// daq utilities
//-------------------------------------------------------------------------

static int socket_daq_module_load(const DAQ_BaseAPI_t* base_api)
{
    if (base_api->api_version != DAQ_BASE_API_VERSION || base_api->api_size != sizeof(DAQ_BaseAPI_t))
        return DAQ_ERROR;

    daq_base_api = *base_api;

    return DAQ_SUCCESS;
}

static int socket_daq_module_unload()
{
    memset(&daq_base_api, 0, sizeof(daq_base_api));
    return DAQ_SUCCESS;
}

static int socket_daq_get_variable_descs(const DAQ_VariableDesc_t** var_desc_table)
{
    *var_desc_table = socket_variable_descriptions;

    return sizeof(socket_variable_descriptions) / sizeof(DAQ_VariableDesc_t);
}

static void clear(SocketContext* socket_context)
{
    if (socket_context->sock_a < 0)
    {
        socket_context->sin_a.sin_addr.s_addr = 0;
        socket_context->sin_a.sin_port = 0;
    }
    if (socket_context->sock_b < 0)
    {
        socket_context->sin_b.sin_addr.s_addr = 0;
        socket_context->sin_b.sin_port = 0;
    }
}

static void set_pkt_hdr(SocketContext* socket_context, SocketMsgDesc* desc, ssize_t len)
{
    struct timeval t;
    gettimeofday(&t, NULL);

    DAQ_PktHdr_t* pkt_hdr = &desc->pkt_hdr;
    pkt_hdr->ts.tv_sec = t.tv_sec;
    pkt_hdr->ts.tv_usec = t.tv_usec;
    pkt_hdr->pktlen = len;

    // use_a already toggled
    if (socket_context->use_a)
    {
        desc->pci.src_addr = socket_context->sin_b.sin_addr.s_addr;
        desc->pci.dst_addr = socket_context->sin_a.sin_addr.s_addr;
        desc->pci.src_port = socket_context->sin_b.sin_port;
        desc->pci.dst_port = socket_context->sin_a.sin_port;
        desc->pci.flags &= ~DAQ_USR_FLAG_TO_SERVER;
    }
    else
    {
        desc->pci.src_addr = socket_context->sin_a.sin_addr.s_addr;
        desc->pci.dst_addr = socket_context->sin_b.sin_addr.s_addr;
        desc->pci.src_port = socket_context->sin_a.sin_port;
        desc->pci.dst_port = socket_context->sin_b.sin_port;
        desc->pci.flags |= DAQ_USR_FLAG_TO_SERVER;
    }

    if (desc->pci.flags & DAQ_USR_FLAG_END_FLOW)
        clear(socket_context);
}

static unsigned socket_daq_read_message(
    SocketContext* socket_context, SocketMsgDesc* desc, DAQ_RecvStatus* rstat)
{
    int* sock = socket_context->use_a ? &socket_context->sock_a : &socket_context->sock_b;
    struct sockaddr_in* psin = socket_context->use_a ? &socket_context->sin_a : &socket_context->sin_b;
    desc->pci.flags = 0;

    unsigned size = sock_poll(socket_context, desc, sock, psin);

    // don't toggle w/o at least one connection so client is always 1st
    if (socket_context->sock_a > -1 || socket_context->sock_b > -1)
        socket_context->use_a = !socket_context->use_a;

    if (*rstat != DAQ_RSTAT_OK && !desc->pci.flags)
        return 0;

    set_pkt_hdr(socket_context, desc, size);

    return size;
}

static int socket_daq_config(SocketContext* socket_context, const DAQ_ModuleConfig_h cfg)
{
    const char* var_key, * var_value;
    daq_base_api.config_first_variable(cfg, &var_key, &var_value);

    if (var_key)
    {
        char* end = NULL;
        socket_context->port = (int)strtol(var_key, &end, 0);
    }

    while (var_key)
    {
        if (!strcmp(var_key, "port"))
        {
            char* end = NULL;
            socket_context->port = (int)strtol(var_value, &end, 0);

            if (*end || socket_context->port <= 0 || socket_context->port > 65535)
            {
                SET_ERROR(socket_context->mod_inst, "%s: bad port (%s)\n", __func__, var_value);
                return DAQ_ERROR;
            }
        }
        else if (!strcmp(var_key, "proto"))
        {
            if (!strcmp(var_value, "tcp"))
                socket_context->ip_proto = IPPROTO_TCP;
            else if (!strcmp(var_value, "udp"))
                socket_context->ip_proto = IPPROTO_UDP;
            else
            {
                SET_ERROR(socket_context->mod_inst, "%s: bad proto (%s)\n", __func__, var_value);
                return DAQ_ERROR;
            }
        }
        else
        {
            SET_ERROR(socket_context->mod_inst, "%s: Unknown variable name: '%s'", DAQ_NAME, var_key);
            return DAQ_ERROR_INVAL;
        }

        daq_base_api.config_next_variable(cfg, &var_key, &var_value);
    }

    if (!socket_context->ip_proto)
        socket_context->ip_proto = IPPROTO_TCP;

    if (!socket_context->port)
        socket_context->port = DEFAULT_PORT;

    socket_context->snaplen = daq_base_api.config_get_snaplen(cfg) ?
        daq_base_api.config_get_snaplen(cfg) : IP_MAXPACKET;

    socket_context->timeout = daq_base_api.config_get_timeout(cfg);
    socket_context->passive = (daq_base_api.config_get_mode(cfg) == DAQ_MODE_PASSIVE);

    return DAQ_SUCCESS;
}

//-------------------------------------------------------------------------
// daq
//-------------------------------------------------------------------------

static void socket_daq_destroy(void* handle)
{
    SocketContext* socket_context = (SocketContext*) handle;

    SocketMsgPool* pool = &socket_context->pool;
    if (pool->pool)
    {
        while (pool->info.size > 0)
            free(pool->pool[--pool->info.size].msg.data);
        free(pool->pool);
        pool->pool = NULL;
    }
    pool->free_list = NULL;
    pool->info.available = 0;
    pool->info.mem_size = 0;

    free(socket_context);
}

static int socket_daq_instantiate(const DAQ_ModuleConfig_h cfg, DAQ_ModuleInstance_h mod_inst, void** handle)
{
    SocketContext* socket_context = calloc(1, sizeof(*socket_context));

    if (!socket_context)
    {
        SET_ERROR(mod_inst, "%s: failed to allocate the socket context!", __func__);
        return DAQ_ERROR_NOMEM;
    }

    if (socket_daq_config(socket_context, cfg) != DAQ_SUCCESS)
    {
        socket_daq_destroy(socket_context);
        return DAQ_ERROR;
    }

    uint32_t pool_size = daq_base_api.config_get_msg_pool_size(cfg);
    if (pool_size == 0)
        pool_size = DEFAULT_POOL_SIZE;

    int rval = create_message_pool(socket_context, pool_size);
    if (rval != DAQ_SUCCESS)
    {
        socket_daq_destroy(socket_context);
        return rval;
    }

    socket_context->mod_inst = mod_inst;
    socket_context->sock_c = socket_context->sock_a = socket_context->sock_b = -1;
    socket_context->use_a = 1;

    *handle = socket_context;
    return DAQ_SUCCESS;
}

static int socket_daq_start(void* handle)
{
    SocketContext* socket_context = (SocketContext*) handle;

    if (sock_setup(socket_context))
        return DAQ_ERROR;

    return DAQ_SUCCESS;
}

static int socket_daq_stop(void* handle)
{
    SocketContext* socket_context = (SocketContext*) handle;
    sock_cleanup(socket_context);
    return DAQ_SUCCESS;
}

static int socket_ioctl(void* handle, DAQ_IoctlCmd cmd, void* arg, size_t arglen)
{
    (void) handle;

    if (cmd == DIOCTL_QUERY_USR_PCI)
    {
        if (arglen != sizeof(DIOCTL_QueryUsrPCI))
            return DAQ_ERROR_INVAL;

        DIOCTL_QueryUsrPCI* qup = (DIOCTL_QueryUsrPCI*)arg;

        if (!qup->msg)
            return DAQ_ERROR_INVAL;

        SocketMsgDesc* desc = (SocketMsgDesc*) qup->msg->priv;
        qup->pci = &desc->pci;

        return DAQ_SUCCESS;
    }
    return DAQ_ERROR_NOTSUP;
}

static int socket_daq_inject(void* handle, DAQ_MsgType type, const void* hdr, const uint8_t* buf, uint32_t len)
{
    (void) hdr;

    if (type != DAQ_MSG_TYPE_PAYLOAD)
        return DAQ_ERROR_NOTSUP;

    SocketContext* socket_context = (SocketContext*) handle;
    int egress = socket_context->use_a ? socket_context->sock_a : socket_context->sock_b;
    int status = sock_send(socket_context, egress, buf, len);

    if (status)
        return DAQ_ERROR;

    socket_context->stats.packets_injected++;
    return DAQ_SUCCESS;
}

static int socket_daq_inject_relative(void* handle, const DAQ_Msg_t* msg, const uint8_t* buf, uint32_t len, int reverse)
{
    SocketContext* socket_context = (SocketContext*) handle;
    int egress;

    (void) msg;

    if (reverse)
        egress = socket_context->use_a ? socket_context->sock_b : socket_context->sock_a;
    else
        egress = socket_context->use_a ? socket_context->sock_a : socket_context->sock_b;

    int status = sock_send(socket_context, egress, buf, len);

    if (status)
        return DAQ_ERROR;

    socket_context->stats.packets_injected++;
    return DAQ_SUCCESS;
}

static unsigned socket_daq_msg_receive(void* handle, const unsigned max_recv, const DAQ_Msg_t* msgs[], DAQ_RecvStatus* rstat)
{
    SocketContext* socket_context = (SocketContext*) handle;
    unsigned idx = 0, miss = 0;

    *rstat = DAQ_RSTAT_OK;

    while (idx < max_recv && ++miss < 2)
    {
        if (socket_context->interrupted)
        {
            socket_context->interrupted = false;
            *rstat = DAQ_RSTAT_INTERRUPTED;
            break;
        }

        SocketMsgDesc* desc = socket_context->pool.free_list;
        if (!desc)
        {
            *rstat = DAQ_RSTAT_NOBUF;
            break;
        }

        unsigned size = socket_daq_read_message(socket_context, desc, rstat);
        if (*rstat != DAQ_RSTAT_OK)
            break;

        if (size)
        {
            desc->msg.data_len = size;
            socket_context->pool.free_list = desc->next;
            desc->next = NULL;
            socket_context->pool.info.available--;
            msgs[idx] = &desc->msg;
            idx++;

            miss = 0;
        }
    }

    return idx;
}

// forward all but drops and blacklists
static const int s_fwd[MAX_DAQ_VERDICT] = { 1, 0, 1, 1, 0, 1 };

static int socket_daq_msg_finalize(void* handle, const DAQ_Msg_t* msg, DAQ_Verdict verdict)
{
    SocketContext* socket_context = (SocketContext*) handle;
    SocketMsgDesc* desc = (SocketMsgDesc*) msg->priv;

    if (verdict >= MAX_DAQ_VERDICT)
        verdict = DAQ_VERDICT_BLOCK;

    socket_context->stats.verdicts[verdict]++;

    if (socket_context->passive || s_fwd[verdict])
    {
        // already toggled use_a, so we get a->b or b->a
        int egress = socket_context->use_a ? socket_context->sock_a : socket_context->sock_b;

        if (sock_send(socket_context, egress, desc->msg.data, msg->data_len))
            return DAQ_ERROR;
    }

    desc->next = socket_context->pool.free_list;
    socket_context->pool.free_list = desc;
    socket_context->pool.info.available++;
    return DAQ_SUCCESS;
}

static int socket_daq_interrupt(void* handle)
{
    SocketContext* socket_context = (SocketContext*) handle;
    socket_context->interrupted = true;
    return DAQ_SUCCESS;
}

static int socket_daq_get_stats(void* handle, DAQ_Stats_t* stats)
{
    SocketContext* socket_context = (SocketContext*) handle;
    *stats = socket_context->stats;
    return DAQ_SUCCESS;
}

static void socket_daq_reset_stats(void* handle)
{
    SocketContext* socket_context = (SocketContext*) handle;
    memset(&socket_context->stats, 0, sizeof(socket_context->stats));
}

static int socket_daq_get_snaplen(void* handle)
{
    SocketContext* socket_context = (SocketContext*) handle;
    return socket_context->snaplen;
}

static uint32_t socket_daq_get_capabilities(void* handle)
{
    (void) handle;
    return DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT | DAQ_CAPA_INJECT_RAW
        | DAQ_CAPA_INTERRUPT | DAQ_CAPA_UNPRIV_START;
}

static int socket_daq_get_datalink_type(void* handle)
{
    (void) handle;
    return DLT_USER;
}

static int socket_daq_set_filter(void* handle, const char* filter)
{
    (void) handle;
    (void) filter;
    return DAQ_ERROR_NOTSUP;
}

static int socket_daq_get_msg_pool_info(void* handle, DAQ_MsgPoolInfo_t* info)
{
    SocketContext* socket_context = (SocketContext*) handle;
    *info = socket_context->pool.info;
    return DAQ_SUCCESS;
}

//-------------------------------------------------------------------------

DAQ_SO_PUBLIC DAQ_ModuleAPI_t DAQ_MODULE_DATA =
{
    .api_version = DAQ_MODULE_API_VERSION,
    .api_size = sizeof(DAQ_ModuleAPI_t),
    .module_version = DAQ_MOD_VERSION,
    .name = DAQ_NAME,
    .type = DAQ_TYPE,
    .load = socket_daq_module_load,
    .unload = socket_daq_module_unload,
    .get_variable_descs = socket_daq_get_variable_descs,
    .instantiate = socket_daq_instantiate,
    .destroy = socket_daq_destroy,
    .set_filter = socket_daq_set_filter,
    .start = socket_daq_start,
    .inject = socket_daq_inject,
    .inject_relative = socket_daq_inject_relative,
    .interrupt = socket_daq_interrupt,
    .stop = socket_daq_stop,
    .ioctl = socket_ioctl,
    .get_stats = socket_daq_get_stats,
    .reset_stats = socket_daq_reset_stats,
    .get_snaplen = socket_daq_get_snaplen,
    .get_capabilities = socket_daq_get_capabilities,
    .get_datalink_type = socket_daq_get_datalink_type,
    .config_load = NULL,
    .config_swap = NULL,
    .config_free = NULL, 
    .msg_receive = socket_daq_msg_receive,
    .msg_finalize = socket_daq_msg_finalize,
    .get_msg_pool_info = socket_daq_get_msg_pool_info,
};
