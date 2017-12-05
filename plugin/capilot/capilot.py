#!/usr/bin/env python2
# -*- coding: utf-8 -*-

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
import subprocess
from subprocess import check_output as qx
from OpenSSL import crypto
from myproxy.client import MyProxyClient
from myproxy.client import MyProxyClientGetError


BITS_RSA = 2048
SCRIPT_CNF = """
#! /bin/bash
RND=`expr $RANDOM \* $RANDOM`
if [ -d /home/tts/.config/watts/capilot ]; then
  DIR=/home/tts/.config/watts/capilot
else
  DIR=.
fi
# DIR=/home/uros/dev/KIT/tts_plugins/capilot_get/temp
export PROXY_SUBJ=$RND
export PROXY_INFO=rfc3820_seq_sect_infinite
export PROXY_PATHLENGTH=""

mkdir -p capilotCA/newcerts
touch capilotCA/index.txt
# serial=$(printf "%x" ${RND} 2> /dev/null)
serial=$(printf "%x" ${RND})
if [ $((${#serial}%2)) = 1 ];then
  serial=0$serial
fi
echo $serial > capilotCA/serial

SUBJ=`openssl x509 -noout -in ENDCERT -subject -nameopt esc_2253,esc_ctrl,utf8,dump_nostr,dump_der,sep_multiline,sname | sed '1d;s:^ *:/:'|tr -d '\n'`
enddate=$(date -ud "$(openssl x509 -enddate -noout -in ENDCERT|cut -d= -f2-)" +%Y%m%d%H%M%SZ)
openssl ca  -batch -notext -in PROXYCSR -cert ENDCERT -keyfile ENDKEY -extfile $DIR/rfc3820.cnf -config $DIR/openssl.cnf -subj "$SUBJ/CN=$RND" -preserveDN -enddate $enddate 2> /dev/null
# openssl ca  -batch -notext -out PROXYCERT -in PROXYCSR -cert ENDCERT -keyfile ENDKEY -extfile $DIR/rfc3820.cnf -config $DIR/openssl.cnf -subj "$SUBJ/CN=$RND" -preserveDN -enddate $enddate &> /dev/null
rm -r capilotCA
"""


def list_params():
    RequestParams = []
    ConfParams = [{'name':'prefix', 'type':'string', 'default':'foobar'},
                  {'name':'client_id', 'type':'string', 'default':'id'},
                  {'name':'client_secret', 'type':'string', 'default':'secret'},
                  {'name':'myproxy_server', 'type':'string', 'default':'proxy_server'},
                  {'name':'myproxy_cert', 'type':'string', 'default':'usercert'},
                  {'name':'myproxy_key', 'type':'string', 'default':'userkey'},
                  {'name':'myproxy_key_pwd', 'type':'string', 'default':'secret'},
                  {'name':'myproxy_server_pwd', 'type':'string', 'default':'secret'},
                  {'name':'proxy_lifetime', 'type':'string', 'default':'43200'},
                  {'name':'host_list', 'type':'string', 'default':''},
                  {'name':'remove_certificate', 'type':'string', 'default':'False'}]
    return json.dumps({'result':'ok', 'conf_params': ConfParams, 'request_params': RequestParams, 'version':'dev'})


def request_certificate(JObject):
    # AccessToken = JObject['access_token']
    AccessToken = JObject['additional_logins'][0]['access_token']
    ConfParams = JObject['conf_params']
    ClientId = ConfParams['client_id']
    MYPROXY_SERVER = ConfParams['myproxy_server']
    ClientSecret = ConfParams['client_secret']

    CSR, KEY = generate_csr(MYPROXY_SERVER)

    Url = "https://ca-pilot.aai.egi.eu/oauth2/getcert"
    Values = {'client_id': ClientId,
              'client_secret': ClientSecret,
              'access_token':AccessToken,
              'certreq':CSR }
    Data = urllib.urlencode(Values)
    # Req = urllib2.Request(Url, Data)
    Req = Url + '?' + Data
    Response = urllib2.urlopen(Req)
    Info = Response.read()
    Creds = [Info, KEY]
    return tuple(Creds)


# generate CSR function
# save also key and csr files
def generate_csr(input_host_name):
    # to be passed as param TODO
    C  = 'DE'
    ST = 'Baden Wuerttemberg'
    L  = 'Karlsruhe'
    O  = 'Karlsruhe Institute of Technology'
    OU = 'SCC'
    # define rsa TYPE and bits
    TYPE_RSA = crypto.TYPE_RSA

    req = crypto.X509Req()
    req.get_subject().CN = input_host_name
    req.get_subject().countryName = C
    req.get_subject().stateOrProvinceName = ST
    req.get_subject().localityName = L
    req.get_subject().organizationName = O
    req.get_subject().organizationalUnitName = OU

    key = crypto.PKey()
    key.generate_key(TYPE_RSA, BITS_RSA)
    req.set_pubkey(key)

    #update sha?
    req.sign(key, "sha256")
    csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
    private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
    csr_temp = csr.splitlines()
    # remove --begin cert req --- and also --- end cert req ---
    csr = csr.replace(csr_temp[0] + '\n', '')
    csr = csr.replace('\n' + csr_temp[-1] + '\n', '')
    creds = [csr, private_key]
    return tuple(creds)


def store_credential(JObject, usercert, userkey):
    username = JObject['watts_userid']
    ConfParams = JObject['conf_params']
    prefix = ConfParams['prefix']
    username = prefix + '_' + username
    MYPROXY_SERVER_PWD = ConfParams['myproxy_server_pwd']
    MYPROXY_CERT = ConfParams['myproxy_cert']
    MYPROXY_KEY = ConfParams['myproxy_key']
    MYPROXY_KEY_PWD = str(ConfParams['myproxy_key_pwd'])
    PROXY_LIFETIME = int(ConfParams['proxy_lifetime'])
    MYPROXY_SERVER = ConfParams['myproxy_server']
    myproxy_clnt = MyProxyClient(hostname = MYPROXY_SERVER)
    myproxy_clnt.store(username, MYPROXY_SERVER_PWD, usercert, userkey, MYPROXY_CERT, MYPROXY_KEY, MYPROXY_KEY_PWD, PROXY_LIFETIME)
    return 0


def deploy_subject(WattsId, X509Name, HostList):
    EntryList = X509Name.get_components()
    DN = ""
    for Entry in EntryList:
        DN = DN + "/%s=%s"%(Entry[0], Entry[1])
    Cmd = "/home/watts/.config/watts/update-gridmap.py add %s '%s' hdf-user"%(WattsId, DN)
    AllGood = execute_on_hosts(Cmd, HostList)
    return AllGood
    # return Res

def execute_on_hosts(Cmd, Hosts):
    # loop through all server and collect the output
    Result = []
    for UserHost in Hosts:
        Host = UserHost.split("@")[1]
        Output = qx(["ssh", UserHost, Cmd])
        try:
            Json = json.loads(Output)
            Json['host'] = Host
            Result.append(Json)
        except:
            UserMsg = "Internal error, please contact the administrator"
            LogMsg = "no json result: %s"%Output
            Result.append({'result':'error', 'host':Host, 'user_msg': UserMsg, 'log_msg':LogMsg})

    AllGood = True
    for Entry in Result:
        if not ('result' in Entry):
            AllGood = False
        elif Entry['result'] != 'ok':
            AllGood = False

    # f = open('ResultFileGridMap.txt', 'w')
    # f.write(str(Result))
    # f.close()

    return AllGood


def create_proxy(ProxyCsr, ProxyCrt, ProxyKey):
    # create safe temp folder
    dirpath = tempfile.mkdtemp()
    tmp_csr = tempfile.mkstemp(dir=dirpath)
    tmp_cert = tempfile.mkstemp(dir=dirpath)
    tmp_key = tempfile.mkstemp(dir=dirpath)
    tmp_script = tempfile.mkstemp(dir=dirpath)
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
    Script_New = SCRIPT_CNF.replace( "ENDCERT", tmp_cert[1] )
    Script_New = Script_New.replace( "ENDKEY", tmp_key[1] )
    Script_New = Script_New.replace( "PROXYCSR", tmp_csr[1] )
    # Script_New = Script_New.replace( "PROXYCERT", tmp_proxy[1] )
    f = open(tmp_script[1], 'w')
    f.write(Script_New)
    f.close()
    # create new proxy
    proxy = subprocess.Popen(["bash", tmp_script[1]], stdout=subprocess.PIPE)
    new_proxy = proxy.communicate()[0]

    # remove temp folder
    shutil.rmtree(dirpath)

    return new_proxy


def put_credential(JObject, usercert, userkey):
    username = JObject['watts_userid']
    ConfParams = JObject['conf_params']
    prefix = ConfParams['prefix']
    username = prefix + '_' + username
    MYPROXY_SERVER_PWD = ConfParams['myproxy_server_pwd']
    MYPROXY_CERT = ConfParams['myproxy_cert']
    MYPROXY_KEY = ConfParams['myproxy_key']
    MYPROXY_KEY_PWD = str(ConfParams['myproxy_key_pwd'])
    # PROXY_LIFETIME = int(ConfParams['proxy_lifetime'])
    MYPROXY_SERVER = ConfParams['myproxy_server']
    myproxy_clnt = MyProxyClient(hostname = MYPROXY_SERVER)
    # get max lifetime for long-lived proxy
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, usercert)
    notBefore = cert.get_notBefore()
    notAfter = cert.get_notAfter()
    notBefore = notBefore[:-1]
    notAfter = notAfter[:-1]
    notAfter_struct = time.strptime(notAfter,  "%Y%m%d%H%M%S")
    notAfter_seconds = time.mktime(notAfter_struct)
    notBefore_struct = time.strptime(notBefore,  "%Y%m%d%H%M%S")
    notBefore_seconds = time.mktime(notBefore_struct)
    MAX_LIFETIME = int(notAfter_seconds - notBefore_seconds - 24*3600)
    conn = myproxy_clnt._initConnection(certFile=MYPROXY_CERT,
                                keyFile=MYPROXY_KEY,
                                keyFilePassphrase=MYPROXY_KEY_PWD)
    conn.connect((MYPROXY_SERVER, 7512))

    # send globus compatibility stuff
    conn.write('0')

    # send store command - ensure conversion from unicode before writing
    cmd = MyProxyClient.PUT_CMD % (username, MYPROXY_SERVER_PWD, MAX_LIFETIME)
    conn.write(str(cmd))
    # process server response
    dat = conn.recv(MyProxyClient.SERVER_RESP_BLK_SIZE)

    respCode, errorTxt = myproxy_clnt._deserializeResponse(dat)
    if respCode:
        raise MyProxyClientGetError(errorTxt)
    dat = conn.recv(MyProxyClient.SERVER_RESP_BLK_SIZE)
    csr_reqst = crypto.load_certificate_request(crypto.FILETYPE_ASN1, dat)
    csr_reqst = crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr_reqst)

    proxyCertTxt = create_proxy(csr_reqst, usercert, userkey)

    # proxyCertTxt = open('/home/tts/.config/watts/capilot/proxycert.pem').read()
    proxyCertTxt = crypto.load_certificate(crypto.FILETYPE_PEM, proxyCertTxt)
    proxyCertTxt = crypto.dump_certificate(crypto.FILETYPE_ASN1, proxyCertTxt)
    endCertTxt = usercert
    endCertTxt = crypto.load_certificate(crypto.FILETYPE_PEM, endCertTxt)
    endCertTxt = crypto.dump_certificate(crypto.FILETYPE_ASN1, endCertTxt)

    # now send the creds to myproxy-server
    # send_creds =str('1'+ proxyCertTxt + endCertTxt + rcauth_cert)
    send_creds =str('1'+ proxyCertTxt + endCertTxt)
    conn.send(send_creds)

    # process server response
    resp = conn.recv(MyProxyClient.SERVER_RESP_BLK_SIZE)
    respCode, errorTxt = myproxy_clnt._deserializeResponse(resp)
    if respCode:
        raise MyProxyClientGetError(errorTxt)

    # not used, implemented above
    # myproxy_clnt.put(username, MYPROXY_SERVER_PWD, usercert, userkey, PROXY_LIFETIME, MYPROXY_CERT, MYPROXY_KEY, MYPROXY_KEY_PWD )
    return 0


def req_and_store_cert(JObject):
    Cert, Key = request_certificate(JObject)
    # store_credential(JObject, Cert, Key)
    put_credential(JObject, Cert, Key)
    ConfParams = JObject['conf_params']
    WattsId = JObject['watts_userid']
    HostsList = ConfParams['host_list'].split()
    subj = crypto.load_certificate(crypto.FILETYPE_PEM, Cert)
    subj = subj.get_subject()
    if not deploy_subject(WattsId, subj, HostsList):
        raise Exception('Deployment of X509 subj in gridmap file failed.')


    # return json.dumps({'result':'ok'})
    return 0


def get_credential(JObject):
    username = JObject['watts_userid']
    AddLogins = JObject['additional_logins']
    ConfParams = JObject['conf_params']
    prefix = ConfParams['prefix']
    username = prefix + '_' + username
    MYPROXY_SERVER_PWD = ConfParams['myproxy_server_pwd']
    MYPROXY_CERT = ConfParams['myproxy_cert']
    MYPROXY_KEY = ConfParams['myproxy_key']
    MYPROXY_KEY_PWD = str(ConfParams['myproxy_key_pwd'])
    PROXY_LIFETIME = int(ConfParams['proxy_lifetime'])
    MYPROXY_SERVER = ConfParams['myproxy_server']
    myproxy_clnt = MyProxyClient(hostname = MYPROXY_SERVER)
    Provider = 'ca_pilot'
    # check if credential exists
    info = myproxy_clnt.info(username, sslCertFile = MYPROXY_CERT, sslKeyFile = MYPROXY_KEY, sslKeyFilePassphrase = MYPROXY_KEY_PWD)
    if info[0] == True and (info[2]['CRED_END_TIME'] <= int(time.time() + 12*60*60)):
        result = myproxy_clnt.destroy(username, sslCertFile = MYPROXY_CERT, sslKeyFile = MYPROXY_KEY, sslKeyFilePassphrase = MYPROXY_KEY_PWD)
        Msg ="Your certificate has expired, therefore it was removed. You will be redirected to login and verify your identity with RCauth to obtain a new one."
        return json.dumps({'result':'oidc_login', 'provider': Provider, 'msg':Msg})
    if info[0] == False and len(AddLogins) == 0:
        Msg ="Currently, we do not have a valid certificate for you. To obtain it, you will be redirected to login and verify your identity with RCauth."
        return json.dumps({'result':'oidc_login', 'provider': Provider, 'msg':Msg})
    if info[0] == False and len(AddLogins) != 0:
        try:
            req_and_store_cert(JObject)
        except Exception as E:
            UserMsg = "Please logout and login again to request a new certificate from RCauth"
            LogMsg = "Request and store certificate failed with %s"%str(E)
            return json.dumps({'result':'error', 'user_msg':UserMsg, 'log_msg':LogMsg})

    # result = myproxy_clnt.logon(username, MYPROXY_SERVER_PWD, lifetime = PROXY_LIFETIME, sslCertFile = MYPROXY_CERT, sslKeyFile = MYPROXY_KEY, sslKeyFilePassphrase = MYPROXY_KEY_PWD)
    result = myproxy_clnt.get(username=username, passphrase=MYPROXY_SERVER_PWD, lifetime = PROXY_LIFETIME, sslCertFile = MYPROXY_CERT, sslKeyFile = MYPROXY_KEY, sslKeyFilePassphrase = MYPROXY_KEY_PWD)
    # join all creds in a single file
    full_credential = ''.join([s for s in result])
    Credential = [{'name':'Proxy certificate', 'type':'textfile', 'value':full_credential, 'rows':30, 'cols':64 , 'save_as': 'x509up_u1000'}]
    return json.dumps({'result':'ok', 'credential': Credential, 'state': username})
    # return json.dumps({'result':'ok', 'credential': Credential, 'state': 'capilot'})


def remove_credential(JObject):
    # username = JObject['watts_userid']
    username = JObject['cred_state']
    ConfParams = JObject['conf_params']
    # MYPROXY_SERVER_PWD = ConfParams['myproxy_server_pwd']
    MYPROXY_CERT = ConfParams['myproxy_cert']
    MYPROXY_KEY = ConfParams['myproxy_key']
    MYPROXY_KEY_PWD = str(ConfParams['myproxy_key_pwd'])
    MYPROXY_SERVER = ConfParams['myproxy_server']
    REMOVE_CERTIFICATE = bool(ConfParams['remove_certificate'])
    myproxy_clnt = MyProxyClient(hostname = MYPROXY_SERVER)
    # check if credential exists
    if REMOVE_CERTIFICATE:
        info = myproxy_clnt.info(username, sslCertFile = MYPROXY_CERT, sslKeyFile = MYPROXY_KEY, sslKeyFilePassphrase = MYPROXY_KEY_PWD)
        # time.sleep(3)
        if info[0]:
            myproxy_clnt.destroy(username, sslCertFile=MYPROXY_CERT, sslKeyFile=MYPROXY_KEY, sslKeyFilePassphrase=MYPROXY_KEY_PWD)

    return json.dumps({'result': 'ok'})


def revoke_info():
    return json.dumps({'result': 'ok'})


def get_jobject():
    Data = ""
    if 'WATTS_PARAMETER' in os.environ:
        Data = os.environ['WATTS_PARAMETER']
    elif len(sys.argv) == 2:
        Data = sys.argv[1]
    else:
        return None
    Json = str(Data)+ '=' * (4 - len(Data) % 4)
    JObject = json.loads(str(base64.urlsafe_b64decode(Json)))
    return JObject


def main():
    try:
        UserMsg = "Internal error, please contact the administrator"
        JObject = get_jobject()
        if JObject is not None:
        # if len(sys.argv) == 2:
        #     Json = str(sys.argv[1])+ '=' * (4 - len(sys.argv[1]) % 4)
            # JObject = json.loads(str(base64.urlsafe_b64decode(Json)))
            Action = JObject['action']
            if Action == "parameter":
                print list_params()
            else:
                if Action == "request":
                    print get_credential(JObject)
                elif Action == "revoke":
                    print remove_credential(JObject)
                else:
                    print json.dumps({"error": "unknown_action", "details": Action})
        else:
            print json.dumps({"error": "no_parameter"})
    except Exception as E:
        TraceBack = traceback.format_exc(),
        LogMsg = "the plugin failed with %s - %s"%(str(E), TraceBack)
        print json.dumps({'result':'error', 'user_msg':UserMsg, 'log_msg':LogMsg})

if __name__ == "__main__":
    main()
