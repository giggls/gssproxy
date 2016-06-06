/* Copyright (C) 2016 the GSS-PROXY contributors, see COPYING for license */

#include "t_utils.h"
#include <unistd.h>

int main(int argc, const char *argv[])
{
    gss_name_t target_name;
    uint32_t ret_maj, ret_min;
    int ret = -1;
    gss_ctx_id_t init_ctx = GSS_C_NO_CONTEXT;
    gss_ctx_id_t accept_ctx = GSS_C_NO_CONTEXT;
    gss_buffer_desc in_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc out_token = GSS_C_EMPTY_BUFFER;
    gss_cred_id_t server_creds = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t delegated_creds = GSS_C_NO_CREDENTIAL;

    if (argc != 3) return -1;

    ret = t_string_to_name(argv[2], &target_name, GSS_C_NT_HOSTBASED_SERVICE);
    if (ret) {
        DEBUG("Failed to import target name from argv[2]\n");
        ret = -1;
        goto done;
    }

    ret_maj = gss_acquire_cred(&ret_min,
                               GSS_C_NO_NAME,
                               GSS_C_INDEFINITE,
                               NULL,
                               GSS_C_BOTH,
                               &server_creds,
                               NULL,
                               NULL);
    if (ret_maj != GSS_S_COMPLETE) {
        DEBUG("gss_acquire_cred() failed\n");
        t_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        ret = -1;
        goto done;
    }

    while (1) {
        ret_maj = gss_init_sec_context(&ret_min,
                                       GSS_C_NO_CREDENTIAL,
                                       &init_ctx,
                                       target_name,
                                       GSS_C_NO_OID,
                                       GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG,
                                       GSS_C_INDEFINITE,
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

        if (!out_token.length == 0) {
            if (ret_maj == GSS_S_COMPLETE) {
                break;
            }

            DEBUG("gss_init_sec_context() no output token\n");
            ret = -1;
            goto done;
        }

        /* in/out intentionally switched */
        ret_maj = gss_accept_sec_context(&ret_min,
                                         &accept_ctx,
                                         server_creds,
                                         &out_token,
                                         GSS_C_NO_CHANNEL_BINDINGS,
                                         NULL,
                                         NULL,
                                         &in_token,
                                         NULL,
                                         NULL,
                                         &delegated_creds);
        if (GSS_ERROR(ret_maj)) {
            DEBUG("gss_accept_sec_context() failed\n");
            t_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
            ret = -1;
            goto done;
        }

        gss_release_buffer(&ret_min, &out_token);
        out_token.value = NULL;

        if (!in_token.length == 0) {
            if (ret_maj == GSS_S_COMPLETE) {
                break;
            }

            DEBUG("gss_accept_sec_context() no output token\n");
            ret = -1;
            goto done;
        }
    }

    if (delegated_creds == GSS_C_NO_CREDENTIAL) {
        DEBUG("gss_accept_sec_context() received no delegated creds\n");
        ret = -1;
        goto done;
    }

    ret = 0;

done:
    gss_release_buffer(&ret_min, &in_token);
    gss_release_buffer(&ret_min, &out_token);
    gss_release_cred(&ret_min, &server_creds);
    gss_release_cred(&ret_min, &delegated_creds);
    return ret;
}
