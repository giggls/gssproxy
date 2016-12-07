#!/usr/bin/python3
# Copyright (C) 2014,2015,2016 - GSS-Proxy contributors; see COPYING for the license

from t_basic import run as run_basic_test

from testlib import *

# Q: What are we testing here ?
#
# A: A client calling gss_init_sec_context() w/o explicitly acquiring
# credentials before hand. [Note: in this case gssproxy uses the 'keytab'
# specified in the store and ignores the 'client_keytab' one].
#
# A gssproxy configruation where the keytab containes multiple keys, and a
# krb5_principal option that sepcify what name we want to use.
#
# We try both names to make sure we target a specific key and not just pick up
# the first in the keytab (which is the normal behavior).

def run(testdir, env, conf):
    setup_multi_keys(testdir, env)
    prefix = conf["prefix"]

    print("Testing multiple keys Keytab with first principal",
          file=sys.stderr)
    conf["prefix"] = prefix + "_1"
    if os.path.exists(os.path.join(testdir, 'gssproxy', 'gpccache')):
        os.unlink(os.path.join(testdir, 'gssproxy', 'gpccache'))
    p1env = {}
    p1env.update(conf["keysenv"])
    p1env['client_name'] = MULTI_UPN
    p1env['KRB5_KTNAME'] = os.path.join(testdir, MULTI_KTNAME)
    update_gssproxy_conf(testdir, p1env, GSSPROXY_MULTI_TEMPLATE)
    os.kill(conf["gpid"], signal.SIGHUP)
    time.sleep(1) #Let gssproxy reload everything
    run_basic_test(testdir, env, conf)

    print("Testing multiple keys Keytab with second principal",
          file=sys.stderr)
    if os.path.exists(os.path.join(testdir, 'gssproxy', 'gpccache')):
            os.unlink(os.path.join(testdir, 'gssproxy', 'gpccache'))
    conf['prefix'] = prefix + "_2"
    p2env = {}
    p2env.update(conf["keysenv"])
    p2env['client_name'] = MULTI_SVC
    p2env['KRB5_KTNAME'] = os.path.join(testdir, MULTI_KTNAME)
    update_gssproxy_conf(testdir, p2env, GSSPROXY_MULTI_TEMPLATE)
    os.kill(conf["gpid"], signal.SIGHUP)
    time.sleep(1) #Let gssproxy reload everything
    run_basic_test(testdir, env, conf)
