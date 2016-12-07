#!/usr/bin/python3
# Copyright (C) 2015,2016 - GSS-Proxy contributors; see COPYING for the license

from testlib import *

def run(testdir, env, conf, expected_failure=False):
    print("Testing impersonate creds...", file=sys.stderr)
    logfile = conf['logfile']

    testenv = {'KRB5CCNAME': os.path.join(testdir, 't' + conf['prefix'] +
                                                   '_impersonate.ccache'),
               'KRB5_KTNAME': conf['keytab'],
               'KRB5_TRACE': os.path.join(testdir, 't' + conf['prefix'] +
                                                   '_impersonate.trace'),
               'GSS_USE_PROXY': 'yes',
               'GSSPROXY_BEHAVIOR': 'REMOTE_FIRST'}
    testenv.update(env)

    cmd = ["./tests/t_impersonate", USR_NAME, conf['svc_name']]
    print("[COMMAND]\n%s\n[ENVIRONMENT]\n%s\n" % (cmd, env), file=logfile)
    logfile.flush()

    p1 = subprocess.Popen(cmd, stderr=subprocess.STDOUT, stdout=logfile,
                          env=testenv, preexec_fn=os.setsid)
    try:
        p1.wait(10)
    except subprocess.TimeoutExpired:
        # p1.returncode is set to None here
        pass
    print_return(p1.returncode, "Impersonate", expected_failure)
