/*--------------------------------------------------------------------------
// Copyright (C) 2017-2019 Cisco and/or its affiliates. All rights reserved.
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
/* daq_regtest.c author Bhagya Tholpady <bbantwal@cisco.com>, Michael Altizer <mialtize@cisco.com> */

#include <daq_module_api.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define DAQ_MOD_VERSION 1
#define DAQ_NAME "regtest"
#define REGTEST_DEBUG_FILE "daq_regtest_debug"
#define REGTEST_CONFIG_FILE "daq_regtest.conf"

#define SET_ERROR(modinst, ...)    daq_base_api.set_errbuf(modinst, __VA_ARGS__)

#define CHECK_SUBAPI(ctxt, fname) \
    (ctxt->subapi.fname.func != NULL)

#define CALL_SUBAPI_NOARGS(ctxt, fname) \
    ctxt->subapi.fname.func(ctxt->subapi.fname.context)

#define CALL_SUBAPI(ctxt, fname, ...) \
    ctxt->subapi.fname.func(ctxt->subapi.fname.context, __VA_ARGS__)

typedef struct
{
    char* buf;
    int config_num;
} RegTestConfig;

typedef struct
{
    DAQ_ModuleInstance_h modinst;
    DAQ_InstanceAPI_t subapi;

    /* Configuration */
    RegTestConfig* cfg;
    unsigned skip;
    unsigned trace;
    uint32_t caps_cfg;
    bool ignore_vlan;

    /* State */
    FILE* debug_fh;
    int daq_config_reads;
} RegTestContext;

// --daq-var skip=10 --daq-var trace=5 would trace packets 11 through 15 only
static DAQ_VariableDesc_t regtest_variable_descriptions[] =
{
    { "skip", "Number of packets to skip before starting to honor the trace option", DAQ_VAR_DESC_REQUIRES_ARGUMENT },
    { "trace", "Number of packets to set the trace enabled flag on", DAQ_VAR_DESC_REQUIRES_ARGUMENT },
    { "caps", "DAQ module capabilities to report (in hex)", DAQ_VAR_DESC_REQUIRES_ARGUMENT },
    { "ignore_vlan", "Set ignore_vlan flag to packet header", DAQ_VAR_DESC_FORBIDS_ARGUMENT },
};

DAQ_BaseAPI_t daq_base_api;

//-------------------------------------------------------------------------

static int regtest_daq_parse_config(RegTestContext *rtc, RegTestConfig** new_config)
{
    long size = 0;
    struct stat sb;

    RegTestConfig* config = calloc(1, sizeof(RegTestConfig));
    if (!config)
    {
        fprintf(stderr, "%s: failed to allocate daq_regtest config", DAQ_NAME);
        return DAQ_ERROR_NOMEM;
    }

    if (stat(REGTEST_CONFIG_FILE, &sb) == -1 && errno == ENOENT)
    {
        *new_config = config;
        return DAQ_SUCCESS;
    }

    FILE* fh = fopen(REGTEST_CONFIG_FILE, "r");

    if (!fh)
    {
        fprintf(stderr, "%s: failed to open the daq_regtest config file", DAQ_NAME);
        free(config);
        return DAQ_ERROR;
    }

    fseek(fh, 0, SEEK_END);
    size = ftell(fh);
    config->buf = (char*) calloc(size, sizeof(char));
    if (!config->buf)
    {
        fprintf(stderr, "%s: failed to allocate daq_regtest buffer", DAQ_NAME);
        free(config);
        fclose(fh);
        return DAQ_ERROR_NOMEM;
    }
    rewind(fh);
    if (fgets(config->buf, size, fh) == NULL)
    {
        fprintf(stderr, "%s: failed to read daq_regtest config file", DAQ_NAME);
        free(config);
        fclose(fh);
        return DAQ_ERROR;
    }
    rtc->daq_config_reads++;
    config->config_num = rtc->daq_config_reads;
    *new_config = config;
    fclose(fh);

    return DAQ_SUCCESS;
}

static void regtest_daq_debug(RegTestContext* rtc, char* msg)
{
    if (rtc->debug_fh)
    {
        fprintf (rtc->debug_fh, "%s\n", msg);
        fprintf (rtc->debug_fh, "daq_regtest config : \n\tbuf = %s \n\tconfig_num = %d \n", 
                rtc->cfg->buf ? rtc->cfg->buf : "N/A", rtc->cfg->config_num);
        fflush(rtc->debug_fh);
    }
}


//-------------------------------------------------------------------------

static int regtest_daq_module_load(const DAQ_BaseAPI_t *base_api)
{
    if (base_api->api_version != DAQ_BASE_API_VERSION || base_api->api_size != sizeof(DAQ_BaseAPI_t))
        return DAQ_ERROR;

    daq_base_api = *base_api;

    return DAQ_SUCCESS;
}

static int regtest_daq_get_variable_descs(const DAQ_VariableDesc_t **var_desc_table)
{
    *var_desc_table = regtest_variable_descriptions;

    return sizeof(regtest_variable_descriptions) / sizeof(DAQ_VariableDesc_t);
}

static int regtest_daq_instantiate(const DAQ_ModuleConfig_h modcfg, DAQ_ModuleInstance_h modinst, void **ctxt_ptr)
{
    RegTestContext* rtc;

    rtc = calloc(1, sizeof(RegTestContext));
    if (!rtc)
    {
        SET_ERROR(modinst, "%s: Couldn't allocate memory for the new daq_regtest context!", DAQ_NAME);
        return DAQ_ERROR_NOMEM;
    }
    rtc->modinst = modinst;

    if (daq_base_api.resolve_subapi(modinst, &rtc->subapi) != DAQ_SUCCESS)
    {
        SET_ERROR(modinst, "%s: Couldn't resolve subapi. No submodule configured?", DAQ_NAME);
        free(rtc);
        return DAQ_ERROR_INVAL;
    }

    int rval = regtest_daq_parse_config(rtc, &rtc->cfg);
    if (rval != DAQ_SUCCESS)
    {
        free(rtc);
        return rval;
    }

    const char *varKey, *varValue;
    daq_base_api.config_first_variable(modcfg, &varKey, &varValue);
    while (varKey)
    {
        if (!strcmp(varKey, "skip"))
            rtc->skip = strtoul(varValue, NULL, 10);
        else if (!strcmp(varKey, "trace"))
            rtc->trace = strtoul(varValue, NULL, 10);
        else if (!strcmp(varKey, "caps"))
        {
            // DAQ capabilities in hex, e.g. caps=0x00004000
            rtc->caps_cfg = strtoul(varValue, NULL, 0);
        }
        else if (!strcmp(varKey, "ignore_vlan"))
            rtc->ignore_vlan = true;
        daq_base_api.config_next_variable(modcfg, &varKey, &varValue);
    }

    rtc->debug_fh = fopen(REGTEST_DEBUG_FILE, "w");

    regtest_daq_debug(rtc, "daq_regtest instantiated");

    *ctxt_ptr = rtc;

    return rval;
}

static void regtest_daq_destroy(void* handle)
{
    RegTestContext* rtc = (RegTestContext*) handle;

    if (rtc->debug_fh)
    {
        fprintf(rtc->debug_fh, "daq_regtest destroyed\n");
        fclose(rtc->debug_fh);
    }

    if (rtc->cfg)
    {
        if (rtc->cfg->buf)
            free(rtc->cfg->buf);
        free(rtc->cfg);
    }

    free(rtc);
}

static int regtest_daq_ioctl(void *handle, DAQ_IoctlCmd cmd, void *arg, size_t arglen)
{
    RegTestContext* rtc = (RegTestContext*) handle;

    if (cmd == DIOCTL_SET_PACKET_TRACE_DATA)
    {
        if (arglen != sizeof(DIOCTL_SetPacketTraceData))
            return DAQ_ERROR_INVAL;
        DIOCTL_SetPacketTraceData *sptd = (DIOCTL_SetPacketTraceData *) arg;
        if (!sptd->msg || (!sptd->trace_data && sptd->trace_data_len != 0))
            return DAQ_ERROR_INVAL;
        printf("DAQ_REGTEST_PKT_TRACE (%d)\n%s\n", sptd->trace_data_len, sptd->trace_data);
    }

    if (CHECK_SUBAPI(rtc, ioctl))
        return CALL_SUBAPI(rtc, ioctl, cmd, arg, arglen);

    return DAQ_ERROR_NOTSUP;
}

static uint32_t regtest_daq_get_capabilities(void* handle)
{
    RegTestContext* rtc = (RegTestContext*) handle;
    uint32_t caps = CALL_SUBAPI_NOARGS(rtc, get_capabilities);
    caps |= rtc->caps_cfg;
    return caps;
}

static int regtest_daq_config_load(void *handle, void **new_config)
{
    RegTestContext* rtc = (RegTestContext*) handle;
    RegTestConfig* newConf;
    int rval = DAQ_SUCCESS;

    if ((rval = regtest_daq_parse_config(rtc, &newConf)) == DAQ_SUCCESS)
    {
        regtest_daq_debug(rtc, "daq_regtest config_load succeeded");
        *new_config = newConf;
    }
    else
        regtest_daq_debug(rtc, "daq_regtest config_load failed");
    return rval;
}

static int regtest_daq_config_swap(void *handle, void *new_config, void **old_config)
{
    RegTestContext* rtc = (RegTestContext*) handle;
    RegTestConfig* config = (RegTestConfig*)new_config;

    *old_config = rtc->cfg;
    rtc->cfg = config;
    regtest_daq_debug(rtc, "daq_regtest config_swap succeeded");

    return DAQ_SUCCESS;
}

static int regtest_daq_config_free(void *handle, void *old_config)
{
    RegTestContext* rtc = (RegTestContext*) handle;
    RegTestConfig* config = (RegTestConfig*)old_config;

    regtest_daq_debug(rtc, "daq_regtest config_free succeeded");

    if (config->buf) 
        free(config->buf);
    free(config);

    return DAQ_SUCCESS;
}

static unsigned regtest_daq_msg_receive(void *handle, const unsigned max_recv, const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat)
{
    RegTestContext* rtc = (RegTestContext*) handle;
    unsigned num_receive = CALL_SUBAPI(rtc, msg_receive, max_recv, msgs, rstat);

    if (rtc->trace > 0)
    {
        for (unsigned idx = 0; idx < num_receive; idx++)
        {
            const DAQ_Msg_t *msg = msgs[idx];

            if (msg->type != DAQ_MSG_TYPE_PACKET)
                continue;

            if (rtc->skip > 0)
                rtc->skip--;
            else if (rtc->trace > 0)
            {
                DAQ_PktHdr_t* pkthdr = (DAQ_PktHdr_t*) msg->hdr;
                pkthdr->flags |= DAQ_PKT_FLAG_TRACE_ENABLED;
                rtc->trace--;
            }
        }
    }

    if (rtc->ignore_vlan)
    {
        for (unsigned idx = 0; idx < num_receive; idx++)
        {
            const DAQ_Msg_t *msg = msgs[idx];
            DAQ_PktHdr_t* pkthdr = (DAQ_PktHdr_t*) msg->hdr;
            pkthdr->flags |= DAQ_PKT_FLAG_IGNORE_VLAN;
        }
    }

    return num_receive;
}


//-------------------------------------------------------------------------

DAQ_SO_PUBLIC DAQ_ModuleAPI_t DAQ_MODULE_DATA =
{
    /* .api_version = */ DAQ_MODULE_API_VERSION,
    /* .api_size = */ sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */ DAQ_MOD_VERSION,
    /* .name = */ DAQ_NAME,
    /* .type = */ DAQ_TYPE_WRAPPER | DAQ_TYPE_INLINE_CAPABLE,
    /* .load = */ regtest_daq_module_load,
    /* .unload = */ NULL,
    /* .get_variable_descs = */ regtest_daq_get_variable_descs,
    /* .instantiate = */ regtest_daq_instantiate,
    /* .destroy = */ regtest_daq_destroy,
    /* .set_filter = */ NULL,
    /* .start = */ NULL,
    /* .inject = */ NULL,
    /* .inject_relative = */ NULL,
    /* .interrupt = */ NULL,
    /* .stop = */ NULL,
    /* .ioctl = */ regtest_daq_ioctl,
    /* .get_stats = */ NULL,
    /* .reset_stats = */ NULL,
    /* .get_snaplen = */ NULL,
    /* .get_capabilities = */ regtest_daq_get_capabilities,
    /* .get_datalink_type = */ NULL,
    /* .config_load = */ regtest_daq_config_load,
    /* .config_swap = */ regtest_daq_config_swap,
    /* .config_free = */ regtest_daq_config_free,
    /* .msg_receive = */ regtest_daq_msg_receive,
    /* .msg_finalize = */ NULL,
    /* .get_msg_pool_info = */ NULL,
};
