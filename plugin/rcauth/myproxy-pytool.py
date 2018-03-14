#!/usr/bin/env python2

import argparse
import logging
import sys
import os
from logging.handlers import RotatingFileHandler
from OpenSSL import crypto
from myproxy.client import MyProxyClient
from myproxy.client import MyProxyClientGetError

PLUGIN_LOGFILE='/var/log/watts/plugin_rcauth.log'

logging.basicConfig(filename=PLUGIN_LOGFILE, level=logging.DEBUG,
        format="[%(asctime)s] {%(filename)s:%(funcName)s:%(lineno)d} %(levelname)s - %(message)s")
logging.info('\n NEW START')


# Parse Options# {{{
def parseOptions():
    '''Parse the commandline options'''
    path_of_executable = sys.argv[0]
    folder_of_executable = os.path.split(path_of_executable)[0]

    parser = argparse.ArgumentParser(
            description='''Myproxy python interface''')
    parser.add_argument('-s', '--MYPROXY_SERVER', help='myproxy server hostname')
    parser.add_argument('-u', '--username')
    parser.add_argument('-c', '--MYPROXY_CERT')
    parser.add_argument('-k', '--MYPROXY_KEY')
    parser.add_argument('-p', '--MYPROXY_KEY_PWD')
    parser.add_argument('-d', '--MYPROXY_SERVER_DN', default='')
    # parser.add_argument('-', '--')
    # parser.add_argument('-', '--')


    return parser.parse_args()
# }}}

args=parseOptions()

print ('key pass: "%s"' % args.MYPROXY_KEY_PWD)

if not args.MYPROXY_SERVER_DN:
    logging.info('this is the constructor:')
    logging.info('hostname: %s' % args.MYPROXY_SERVER)
    myproxy_clnt   = MyProxyClient(hostname = args.MYPROXY_SERVER)
else:
    myproxy_clnt   = MyProxyClient(hostname = args.MYPROXY_SERVER, serverDN = args.MYPROXY_SERVER_DN)

logging.info('this is the info call:')
logging.info('username: %s'             % args.username)
logging.info('sslCertFile: %s'          % args.MYPROXY_CERT)
logging.info('sslKeyFile: %s'           % args.MYPROXY_KEY)
logging.info('sslKeyFilePassphrase: %s' % args.MYPROXY_KEY_PWD)

info               = myproxy_clnt.info(args.username, 
                                       sslCertFile          = args.MYPROXY_CERT,
                                       sslKeyFile           = args.MYPROXY_KEY,
                                       sslKeyFilePassphrase = args.MYPROXY_KEY_PWD)
print (str(info))
