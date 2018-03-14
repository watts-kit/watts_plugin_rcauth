#!/usr/bin/env python2
# vim: tw=100
'''rcauth plugin for WaTTS.
Authors:  Uros.Stevanovic@kit.edu
          Marcus.Hardt@kit.edu

License: MIT License'''
# -*- coding: utf-8 -*-
# pylint: disable=bad-whitespace, invalid-name, logging-not-lazy

import urllib
import urllib2
import json
import base64
import sys
import traceback
import time
import os
import tempfile
import shutil
import logging
from logging.handlers import RotatingFileHandler
import subprocess # this and the selected functions of subprocess below?
from subprocess import check_output as qx # why qx???
from OpenSSL import crypto
from myproxy.client import MyProxyClient
from myproxy.client import MyProxyClientGetError
import passwordclib.client
### FIXME: All docstrings are missing

BITS_RSA = 2048
### Further remarks are inline
SCRIPT_CNF = """
#! /bin/bash
RND=`expr $RANDOM \* $RANDOM`
TMPDIR=@TMPDIR@
CONFIGDIR=@CONFIGDIR@

export PROXY_SUBJ=$RND
export PROXY_INFO=rfc3820_seq_sect_infinite
export PROXY_PATHLENGTH=""
### Why to these need to be exported?

pushd ./ > /dev/null
cd $TMPDIR

mkdir -p rcauthCA/newcerts
touch rcauthCA/index.txt
# serial=$(printf "%x" ${RND} 2> /dev/null)
serial=$(printf "%x" ${RND})
if [ $((${#serial}%2)) = 1 ];then
  ### Please add a comment about what the above statement does
  serial=0$serial
fi
echo $serial > rcauthCA/serial

SUBJ=`openssl x509 -noout -in @ENDCERT@ -subject -nameopt esc_2253,esc_ctrl,utf8,dump_nostr,dump_der,sep_multiline,sname | sed '1d;s:^ *:/:'|tr -d '\n'`
enddate=$(date -ud "$(openssl x509 -enddate -noout -in @ENDCERT@|cut -d= -f2-)" +%Y%m%d%H%M%SZ)
### One could validate if enddate now contains a sensible value 
### One *should* check the return value of openssl!
openssl ca  -batch -notext -in @PROXYCSR@ -cert @ENDCERT@ -keyfile @ENDKEY@ -extfile $CONFIGDIR/rfc3820.cnf -config $CONFIGDIR/openssl.cnf -subj "$SUBJ/CN=$RND" -preserveDN -enddate $enddate 2> /dev/null
# openssl ca  -batch -notext -out PROXYCERT -in @PROXYCSR@ -cert @ENDCERT@ -keyfile @ENDKEY@ -extfile $CONFIGDIR/rfc3820.cnf -config $CONFIGDIR/openssl.cnf -subj "$SUBJ/CN=$RND" -preserveDN -enddate $enddate &> /dev/null

popd > /dev/null
echo " rm -rf $TMPDIR " > /tmp/rcauth.log
# rm -r rcauthCA
"""

def tracer(fn):
    from itertools import chain
    def wrapped(*v, **k):
        name = fn.__name__
        logging.info ("%s(%s)" % (name, ", ".join(map(repr, chain(v, k.values())))))
        return fn(*v, **k)
    return wrapped

def list_params():
    RequestParams = []
    ConfParams = [{'name':'prefix'             , 'type':'string' , 'default':'foobar'}       ,
                  {'name':'oauth2_url'         , 'type':'string' , 'default':'https://ca-pilot.aai.egi.eu/oauth2/getcert'} ,
                  {'name':'plugin_logfile'     , 'type':'string' , 'default':'/var/log/watts/caplugin.log'}                ,
                  {'name':'client_id'          , 'type':'string' , 'default':'id'}           ,
                  {'name':'client_secret_key'  , 'type':'string' , 'default':'secret'}       ,
                  {'name':'myproxy_server'     , 'type':'string' , 'default':'proxy_server'} ,
                  {'name':'myproxy_cert'       , 'type':'string' , 'default':'usercert'}     ,
                  {'name':'myproxy_key'        , 'type':'string' , 'default':'userkey'}      ,
                  {'name':'myproxy_server_pwd_key_id' , 'type':'string' , 'default':''}             ,
                  {'name':'myproxy_server_dn'  , 'type':'string' , 'default':''}             ,
                  {'name':'proxy_lifetime'     , 'type':'string' , 'default':'43200'}        ,
                  {'name':'host_list'          , 'type':'string' , 'default':''}             ,
                  {'name':'rcauth_op_entry'    , 'type':'string' , 'default':''}             ,
                  {'name':'plugin_base_dir'    , 'type':'string' , 'default':''}             ,
                  {'name':'remove_certificate' , 'type':'string' , 'default':'False'}]
    return json.dumps({'result':'ok', 'conf_params': ConfParams, 'request_params': RequestParams, 'version':'dev'})

def request_certificate(JObject):
    AccessToken    = JObject['additional_logins'][0]['access_token']
    ConfParams     = JObject['conf_params']
    ClientId       = ConfParams['client_id']
    MYPROXY_SERVER = ConfParams['myproxy_server']
    OAUTH_URL      = ConfParams['oauth2_url']
    ClientSecretKey= ConfParams['client_secret_key']
    ClientSecret   = get_secret_from_passwordd(ClientSecretKey)

    CSR, KEY       = generate_csr(MYPROXY_SERVER)

    Values         = {'client_id': ClientId,
                      'client_secret': ClientSecret,
                      'access_token':AccessToken,
                      'certreq':CSR}
    Data           = urllib.urlencode(Values)
    Req            = OAUTH_URL + '?' + Data
    Response       = urllib2.urlopen(Req)
    Info           = Response.read()
    # INFO is actually the signed certificate!!
    Creds          = [Info, KEY]
    return tuple(Creds)

### where do these comments belong?
# generate CSR function
# save also key and csr files

def get_secret_from_passwordd(key_id):
    '''get secret from passwordd and fail if not'''
    logging.info("getting password for '%s' from passwordd" % key_id)
    secret = passwordclib.client.get_secret(key_id)
    if not secret:
        logging.error("Could not get password for '%s' from passwordd" % key_id)
        print ("Could not get password for '%s' from passwordd" % key_id)
        raise
        exit(2)
    logging.info("  => sucess (getting '%s')" % key_id)
    return secret

def generate_csr(input_host_name):
    # These are apparantly ignored at the CA
    C  = 'xx'
    ST = 'xxxxxxxxxxxxxxxxxx'
    L  = 'xxxxxxxxx'
    O  = 'xxxxxxxxx'
    OU = 'XXX'
    # define rsa TYPE and bits
    TYPE_RSA = crypto.TYPE_RSA

    req = crypto.X509Req()
    req.get_subject().CN                     = input_host_name
    req.get_subject().countryName            = C
    req.get_subject().stateOrProvinceName    = ST
    req.get_subject().localityName           = L
    req.get_subject().organizationName       = O
    req.get_subject().organizationalUnitName = OU

    key = crypto.PKey()
    key.generate_key(TYPE_RSA, BITS_RSA)
    req.set_pubkey(key)

    #update sha?
    req.sign(key, "sha256")
    csr         = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
    private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
    csr_temp    = csr.splitlines()
    # remove --begin cert req --- and also --- end cert req ---
    csr         = csr.replace(csr_temp[0] + '\n', '')
    csr         = csr.replace('\n' + csr_temp[-1] + '\n', '')
    creds       = [csr, private_key]
    return tuple(creds)

def store_credential(JObject, usercert, userkey):
    username           = JObject['watts_userid']
    ConfParams         = JObject['conf_params']
    prefix             = ConfParams['prefix']
    username           = prefix + '_' + username
    MYPROXY_SERVER_PWD_KEY_ID = ConfParams['myproxy_server_pwd_key_id']
    MYPROXY_CERT       = ConfParams['myproxy_cert']
    MYPROXY_KEY        = ConfParams['myproxy_key']
    PROXY_LIFETIME     = int(ConfParams['proxy_lifetime'])
    MYPROXY_SERVER     = ConfParams['myproxy_server']
    MYPROXY_SERVER_DN  = ConfParams['myproxy_server_dn']
    if not MYPROXY_SERVER_DN:
        myproxy_clnt       = MyProxyClient(hostname = MYPROXY_SERVER, CACertDir="/etc/grid-security/certificates")
    else:
        myproxy_clnt       = MyProxyClient(hostname = MYPROXY_SERVER, serverDN = MYPROXY_SERVER_DN, CACertDir="/etc/grid-security/certificates")
    MYPROXY_SERVER_PWD = get_secret_from_passwordd(MYPROXY_SERVER_PWD_KEY_ID)
    myproxy_clnt.store(username              = username,
                       passphrase            = MYPROXY_SERVER_PWD,
                       certFile              = usercert,
                       keyFile               = userkey,
                       sslCertFile           = MYPROXY_CERT,
                       sslKeyFile            = MYPROXY_KEY,
                       sslKeyFilePhassphrase = None,
                       lifetime              = PROXY_LIFETIME,
                       force                 = True)
    return 0

def deploy_subject(WattsId, X509Name, HostList):
    EntryList = X509Name.get_components()
    DN        = ""
    for Entry in EntryList:
        DN  = DN + "/%s=%s"%(Entry[0], Entry[1])
    ### FIXME: this needs to be hardcoded??
    ### The good news is that this function isn't called if host_list is empty
    Cmd     = "/home/watts/.config/watts/update-gridmap.py add %s '%s' hdf-user"%(WattsId, DN)
    AllGood = execute_on_hosts(Cmd, HostList)
    return AllGood
    # return Res

def execute_on_hosts(Cmd, Hosts):
    # loop through all server and collect the output
    Result = []
    for UserHost in Hosts:
        Host   = UserHost.split("@")[1]
        Output = qx(["ssh", UserHost, Cmd])
        try:
            Json = json.loads(Output)
            Json['host'] = Host
            Result.append(Json)
        except:
            UserMsg = "Internal error, please contact the administrator"
            LogMsg  = "no json result: %s"%Output
            Result.append({'result':'error', 'host':Host, 'user_msg': UserMsg, 'log_msg':LogMsg})

    AllGood = True
    for Entry in Result:
        if not 'result' in Entry:
            AllGood = False
        elif Entry['result'] != 'ok':
            AllGood = False

    # f = open('ResultFileGridMap.txt', 'w')
    # f.write(str(Result))
    # f.close()

    return AllGood

def create_proxy(ProxyCsr, ProxyCrt, ProxyKey, plugin_base_dir='id10t'):
    # create safe temp folder
    logging.info('starting create_proxy.')
    # logging.info('parameters are: ')
    # logging.info('    ProxyCsr: "%s"' % ProxyCsr)
    # logging.info('    ProxyCrt: "%s"' % ProxyCrt)
    # logging.info('    ProxyKey: "%s"' % ProxyKey)
    dirpath    = tempfile.mkdtemp()
    tmp_csr    = tempfile.mkstemp(dir = dirpath)
    tmp_cert   = tempfile.mkstemp(dir = dirpath)
    tmp_key    = tempfile.mkstemp(dir = dirpath)
    tmp_script = tempfile.mkstemp(dir = dirpath)
    tmp_dir    = tempfile.mkdtemp(dir = dirpath)
    # tmp_proxy = tempfile.mkstemp(dir=dirpath)

    # create csr file
    f = open(tmp_csr[1], 'w')
    f.write(ProxyCsr)
    f.close()

    # create crt file
    f = open(tmp_cert[1], 'w')
    f.write(ProxyCrt)
    f.close()

    # create key file
    f = open(tmp_key[1], 'w')
    f.write(ProxyKey)
    f.close()

    # create script file
    Script_New = SCRIPT_CNF.replace( "@ENDCERT@"  , tmp_cert[1] )
    Script_New = Script_New.replace( "@ENDKEY@"   , tmp_key[1] )
    Script_New = Script_New.replace( "@PROXYCSR@" , tmp_csr[1] )
    Script_New = Script_New.replace( "@TMPDIR@"   , tmp_dir )
    Script_New = Script_New.replace( "@CONFIGDIR@", plugin_base_dir )
    # Script_New = Script_New.replace( "PROXYCERT", tmp_proxy[1] ) ### FIXME: Why is this commented? PROXYCERT is part of the script!!!
    f = open(tmp_script[1], 'w')
    f.write(Script_New)
    f.close()
    # create new proxy
    proxy     = subprocess.Popen(["bash", tmp_script[1]], stdout = subprocess.PIPE)
    ### FIXME: Check error codes and potentially also stdout!
    new_proxy = proxy.communicate()[0]

    # remove temp folder
    ### UMMM... this temp folder contains a private key!!!
    shutil.rmtree(dirpath)

    return new_proxy

# @tracer
def put_credential(JObject, usercert, userkey):
    username           = JObject['watts_userid']
    ConfParams         = JObject['conf_params']
    prefix             = ConfParams['prefix']
    username           = prefix + '_' + username
    plugin_base_dir    = ConfParams['plugin_base_dir']
    MYPROXY_SERVER_PWD_KEY_ID = ConfParams['myproxy_server_pwd_key_id']
    MYPROXY_CERT       = ConfParams['myproxy_cert']
    MYPROXY_KEY        = ConfParams['myproxy_key']
    # PROXY_LIFETIME   = int(ConfParams['proxy_lifetime'])
    MYPROXY_SERVER     = ConfParams['myproxy_server']
    MYPROXY_SERVER_DN  = ConfParams['myproxy_server_dn']
    if not MYPROXY_SERVER_DN:
        myproxy_clnt       = MyProxyClient(hostname = MYPROXY_SERVER, CACertDir="/etc/grid-security/certificates")
    else:
        myproxy_clnt       = MyProxyClient(hostname = MYPROXY_SERVER, serverDN = MYPROXY_SERVER_DN, CACertDir="/etc/grid-security/certificates")

    # get max lifetime for long-lived proxy
    cert               = crypto.load_certificate(crypto.FILETYPE_PEM, usercert)
    notBefore          = cert.get_notBefore()
    notAfter           = cert.get_notAfter()
    notBefore          = notBefore[:-1]
    notAfter           = notAfter[:-1]
    notAfter_struct    = time.strptime(notAfter,  "%Y%m%d%H%M%S")
    notAfter_seconds   = time.mktime(notAfter_struct)
    notBefore_struct   = time.strptime(notBefore,  "%Y%m%d%H%M%S")
    notBefore_seconds  = time.mktime(notBefore_struct)
    MAX_LIFETIME       = int(notAfter_seconds - notBefore_seconds - 24*3600)
    conn               = myproxy_clnt._initConnection(certFile = MYPROXY_CERT,
                                                      keyFile=MYPROXY_KEY)
    conn.connect((MYPROXY_SERVER, 7512))

    # send globus compatibility stuff
    conn.write('0')

    # send store command - ensure conversion from unicode before writing
    ### Why is this not using myproxy_clnt instance, but the class???
    logging.info('getting password for "%s" from passwordd' % MYPROXY_SERVER_PWD_KEY_ID)
    MYPROXY_SERVER_PWD = get_secret_from_passwordd(MYPROXY_SERVER_PWD_KEY_ID)
    logging.info('    => successs')
    logging.info('calling myproxy.put')
    cmd = MyProxyClient.PUT_CMD % (username, MYPROXY_SERVER_PWD, MAX_LIFETIME)
    logging.info('sent cmd to myproxy: %s' % str(cmd))
    conn.write(str(cmd))
    # process server response
    ### Why is this not using myproxy_clnt instance, but the class???
    dat = conn.recv(MyProxyClient.SERVER_RESP_BLK_SIZE)
    logging.info('returned dat:: %s' % str(dat))

    respCode, errorTxt = myproxy_clnt._deserializeResponse(dat)
    if respCode:
        raise MyProxyClientGetError("put_credential:1: %s (%s)" % (errorTxt, respCode))
    dat            = conn.recv(MyProxyClient.SERVER_RESP_BLK_SIZE)
    csr_reqst      = crypto.load_certificate_request(crypto.FILETYPE_ASN1, dat)
    csr_reqst      = crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr_reqst)

    logging.info ('calling create_proxy')
    # logging.info ('csr_reqst: %s' % csr_reqst)
    # logging.info ('usercert: %s' % usercert)
    # logging.info ('userkey: %s' % userkey)
    # logging.info ('plugin_base_dir: %s' % plugin_base_dir)
    proxyCertTxt   = create_proxy(csr_reqst, usercert, userkey, plugin_base_dir)
    # logging.info ('proxyCertTxt: "%s"' % proxyCertTxt)

    proxyCertTxt   = crypto.load_certificate(crypto.FILETYPE_PEM, proxyCertTxt)
    proxyCertTxt   = crypto.dump_certificate(crypto.FILETYPE_ASN1, proxyCertTxt)
    endCertTxt     = usercert
    endCertTxt     = crypto.load_certificate(crypto.FILETYPE_PEM, endCertTxt)
    endCertTxt     = crypto.dump_certificate(crypto.FILETYPE_ASN1, endCertTxt)

    # now send the creds to myproxy-server
    # send_creds   = str('1'+ proxyCertTxt + endCertTxt + rcauth_cert)
    send_creds     = str('1'+ proxyCertTxt + endCertTxt)
    conn.send(send_creds)

    # process server response
    resp               = conn.recv(MyProxyClient.SERVER_RESP_BLK_SIZE)
    respCode, errorTxt = myproxy_clnt._deserializeResponse(resp)
    if respCode:
        raise MyProxyClientGetError("put_credential:1: " + errorTxt)

    logging.info("put_credential successfully finished")
    return 0

def req_and_store_cert(JObject):
    Cert, Key  = request_certificate(JObject)
    # store_credential(JObject, Cert, Key)
    put_credential(JObject, Cert, Key)
    ConfParams = JObject['conf_params']
    WattsId    = JObject['watts_userid']
    HostsList  = ConfParams['host_list'].split()
    subj       = crypto.load_certificate(crypto.FILETYPE_PEM, Cert)
    subj       = subj.get_subject()
    if not deploy_subject(WattsId, subj, HostsList):
        logging.info('Problems deploying the subject')
        raise Exception("req_and_store_cert: " + 'Deployment of X509 subj in gridmap file failed.')

    # return json.dumps({'result':'ok'})
    return 0

def get_credential(JObject):
    username           = JObject['watts_userid']
    AddLogins          = JObject['additional_logins']
    ConfParams         = JObject['conf_params']
    prefix             = ConfParams['prefix']
    username           = prefix + '_' + username
    MYPROXY_SERVER_PWD_KEY_ID = ConfParams['myproxy_server_pwd_key_id']
    MYPROXY_CERT       = ConfParams['myproxy_cert']
    MYPROXY_KEY        = ConfParams['myproxy_key']
    PROXY_LIFETIME     = int(ConfParams['proxy_lifetime'])
    MYPROXY_SERVER     = ConfParams['myproxy_server']
    MYPROXY_SERVER_DN  = ConfParams['myproxy_server_dn']
    Provider           = ConfParams['rcauth_op_entry']
    if not MYPROXY_SERVER_DN:
        logging.info('this is the constructor:')
        logging.info('hostname: %s' % MYPROXY_SERVER)
        myproxy_clnt       = MyProxyClient(hostname = MYPROXY_SERVER, CACertDir="/etc/grid-security/certificates")
    else:
        myproxy_clnt       = MyProxyClient(hostname = MYPROXY_SERVER, serverDN = MYPROXY_SERVER_DN, CACertDir="/etc/grid-security/certificates")
    # check if credential exists

    logging.info('this is the info call:')
    logging.info('username: %s'             % username)
    logging.info('sslCertFile: %s'          % MYPROXY_CERT)
    logging.info('sslKeyFile: %s'           % MYPROXY_KEY)

    info               = myproxy_clnt.info(username, 
                                           sslCertFile = MYPROXY_CERT, 
                                           sslKeyFile = MYPROXY_KEY)
    logging.info('Just got this info from myproxy: "%s"' % str(info))
    if info[0] == True and (info[2]['CRED_END_TIME'] <= int(time.time() + 12*60*60)):
        result = myproxy_clnt.destroy(username,
                                      sslCertFile = MYPROXY_CERT,
                                      sslKeyFile = MYPROXY_KEY)
        Msg ='Your certificate has expired, therefore it was removed. '+\
             'You will be redirected to login and verify your '+\
             'identity with RCauth to obtain a new one.'
        return json.dumps({'result':'oidc_login', 'provider': Provider, 'msg':Msg})
    if info[0] == False and len(AddLogins) == 0:
        Msg ='Currently, we do not have a valid certificate for you. '+\
             'To obtain it, you will be redirected to login and verify your identity with RCauth.'
        return json.dumps({'result':'oidc_login', 'provider': Provider, 'msg':Msg})
    if info[0] == False and len(AddLogins) != 0:
        try:
            req_and_store_cert(JObject)
        except Exception as E:
            UserMsg = 'Please logout and login again to request a new certificate from RCauth'
            logging.info = 'Request and store certificate failed with "%s"'%str(E)
            LogMsg = 'Request and store certificate failed with "%s"'%str(E)
            raise
            return json.dumps({'result':'error', 'user_msg':UserMsg, 'log_msg':LogMsg})

    MYPROXY_SERVER_PWD = get_secret_from_passwordd(MYPROXY_SERVER_PWD_KEY_ID)
    logging.info ("calling 'myproxy.get'")
    result = myproxy_clnt.get(username=username,
                              passphrase=MYPROXY_SERVER_PWD,
                              lifetime = PROXY_LIFETIME,
                              sslCertFile = MYPROXY_CERT,
                              sslKeyFile = MYPROXY_KEY)
    # join all creds in a single file
    full_credential = ''.join([s for s in result])
    Credential = [{'name':'Proxy certificate',
                   'type':'textfile',
                   'value':full_credential,
                   'rows':30, 'cols':64 ,
                   'save_as': 'x509up_u1000'}]
    return json.dumps({'result':'ok', 'credential': Credential, 'state': username})

def remove_credential(JObject):
    # username           = JObject['watts_userid']
    username             = JObject['cred_state']
    ConfParams           = JObject['conf_params']
    # MYPROXY_SERVER_PWD = ConfParams['myproxy_server_pwd']
    MYPROXY_CERT         = ConfParams['myproxy_cert']
    MYPROXY_KEY          = ConfParams['myproxy_key']
    MYPROXY_SERVER       = ConfParams['myproxy_server']
    MYPROXY_SERVER_DN    = ConfParams['myproxy_server_dn']
    REMOVE_CERTIFICATE   = bool(ConfParams['remove_certificate'])
    if not MYPROXY_SERVER_DN:
        myproxy_clnt       = MyProxyClient(hostname = MYPROXY_SERVER, CACertDir="/etc/grid-security/certificates")
    else:
        myproxy_clnt       = MyProxyClient(hostname = MYPROXY_SERVER, serverDN = MYPROXY_SERVER_DN, CACertDir="/etc/grid-security/certificates")
    # check if credential exists
    if REMOVE_CERTIFICATE:
        info = myproxy_clnt.info(username,
                                 sslCertFile = MYPROXY_CERT,
                                 sslKeyFile = MYPROXY_KEY)
        # time.sleep(3)
        if info[0]:
            myproxy_clnt.destroy(username,
                                 sslCertFile=MYPROXY_CERT,
                                 sslKeyFile=MYPROXY_KEY)
    return json.dumps({'result': 'ok'})

def revoke_info():
    return json.dumps({'result': 'ok'})
    ### FIXME: The fact that this is not implemented needs to be well known and well documented

def get_jobject():
    Data = ""
    if len(sys.argv) == 2:
        Data = sys.argv[1]
    else:
        Data = sys.stdin.read()
    Json = str(Data)+ '=' * (4 - len(Data) % 4)
    JObject = json.loads(str(base64.urlsafe_b64decode(Json)))
    return JObject

def main():
    # setup logging:
    PLUGIN_LOGFILE = '/var/log/watts/plugin_rcauth.log'
    handler = RotatingFileHandler(PLUGIN_LOGFILE, maxBytes=10000, backupCount=1)
    logging.basicConfig(filename=PLUGIN_LOGFILE, level=logging.DEBUG,
            format="[%(asctime)s] {%(filename)s:%(funcName)s:%(lineno)d} %(levelname)s - %(message)s")
    logging.info('\n NEW START')

    try:
        UserMsg = "Internal error, please contact the administrator"
        JObject = get_jobject()
        if JObject is not None:
            # Setup logging:
                
        # if len(sys.argv) == 2:
        #     Json = str(sys.argv[1])+ '=' * (4 - len(sys.argv[1]) % 4)
            # JObject = json.loads(str(base64.urlsafe_b64decode(Json)))
            Action = JObject['action']
            if Action == "parameter":
                print (list_params())
            else:
                if Action == "request":
                    print (get_credential(JObject))
                elif Action == "revoke":
                    print (remove_credential(JObject))
                else:
                    print (json.dumps({"error": "unknown_action", "details": Action}))
        else:
            print (json.dumps({"error": "no_parameter"}))
    except Exception as E:
        TraceBack = traceback.format_exc(),
        LogMsg = "the plugin failed with %s - %s"%(str(E), TraceBack)
        print (json.dumps({'result':'error', 'user_msg':UserMsg, 'log_msg':LogMsg}))

if __name__ == "__main__":
    main()
