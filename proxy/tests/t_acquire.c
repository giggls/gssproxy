/* Copyright (C) 2014, 2016 the GSS-PROXY contributors, see COPYING for license */

#include "t_utils.h"
#include <unistd.h>

int main(int argc, const char *argv[])
{
    char buffer[MAX_RPC_SIZE];
    uint32_t buflen;
    gss_cred_id_t cred_handle = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t init_ctx = GSS_C_NO_CONTEXT;
    gss_ctx_id_t accept_ctx = GSS_C_NO_CONTEXT;
    gss_buffer_desc in_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc out_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc user_password = GSS_C_EMPTY_BUFFER;
    gss_name_t target_name;
    gss_OID_set_desc oid_set = { 1, discard_const(gss_mech_krb5) };
    uint32_t ret_maj;
    uint32_t ret_min;
    uint32_t time_rec;
    int ret = -1;

    if (argc != 2) return -1;

    ret = t_string_to_name(argv[1], &target_name,
                           GSS_C_NT_HOSTBASED_SERVICE);
    if (ret) {
        DEBUG("Failed to import server name from argv[1]\n");
        ret = -1;
        goto done;
    }

    ret_maj = gss_acquire_cred(&ret_min,
                               GSS_C_NO_NAME,
                               GSS_C_INDEFINITE,
                               &oid_set,
                               GSS_C_INITIATE,
                               &cred_handle,
                               NULL, NULL);
    if (ret_maj != GSS_S_COMPLETE) {
        DEBUG("gss_acquire_cred() failed\n");
        t_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        ret = -1;
        goto done;
    }

    ret_maj = gss_store_cred(&ret_min, cred_handle, GSS_C_INITIATE,
                             GSS_C_NULL_OID, 1, 1, NULL, NULL);
    if (ret_maj) {
        DEBUG("Error saving credentials\n");
        t_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        ret = -1;
        goto done;
    }

    gss_release_cred(&ret_min, &cred_handle);

    while (1) {
        ret_maj = gss_init_sec_context(&ret_min,
                                       GSS_C_NO_CREDENTIAL,
                                       &init_ctx,
                                       target_name,
                                       GSS_C_NO_OID,
                                       GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG,
                                       0,
                                       GSS_C_NO_CHANNEL_BINDINGS,
                                       &in_token,
                                       NULL,
                                       &out_token,
                                       NULL,
                                       NULL);
        if (GSS_ERROR(ret_maj)) {
            DEBUG("gss_init_sec_context() failed\n");
            t_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
            ret = -1;
            goto done;
        }

        gss_release_buffer(&ret_min, &in_token);
        in_token.value = NULL;

        if (!out_token.length) {
            if (ret_maj == GSS_S_COMPLETE) {
                /* negotiation complete */
                break;
            }

            DEBUG("No output token from init_sec_context?");
            ret = -1;
            goto done;
        }

        /* in/out token inverted here intentionally */
        ret_maj = gss_accept_sec_context(&ret_min,
                                         &accept_ctx,
                                         GSS_C_NO_CREDENTIAL,
                                         &out_token,
                                         GSS_C_NO_CHANNEL_BINDINGS,
                                         NULL,
                                         NULL,
                                         &in_token,
                                         NULL,
                                         NULL,
                                         NULL);
        if (GSS_ERROR(ret_maj)) {
            DEBUG("Error accepting context\n");
            t_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
            ret = -1;
            goto done;
        }

        gss_release_buffer(&ret_min, &out_token);
        out_token.value = NULL;

        if (!in_token.length) {
            if (ret_maj == GSS_S_COMPLETE) {
                /* negotiation complete */
                break;
            }

            DEBUG("No output token from accept_sec_context?");
            ret = -1;
            goto done;
        }
    }

    ret = 0;

done:
    gss_release_buffer(&ret_min, &in_token);
    gss_release_buffer(&ret_min, &out_token);
    gss_release_cred(&ret_min, &cred_handle);
    return ret;
}
