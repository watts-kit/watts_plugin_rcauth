# Plugin Configuration #
The rcauth plugin needs several configuration variables defined in watts.conf:
Here is an example:

```
 service.RCauth_plugin.description                      = Certificates from RCauth Demo CA
 service.RCauth_plugin.credential_limit                 = infinite
 service.RCauth_plugin.connection.type                  = local   
 service.RCauth_plugin.cmd_env_use                      = true    
 service.RCauth_plugin.parallel_runner                  = 1       
 service.RCauth_plugin.authz.allow.any.sub.any          = true    
 service.RCauth_plugin.pass_access_token                = true    
 service.RCauth_plugin.allow_same_state                 = true    
 service.RCauth_plugin.cmd                              = /var/lib/watts/plugins/watts_plugin_rcauth/plugin/rcauth/rcauth.py
 service.RCauth_plugin.plugin.plugin_base_dir           = /var/lib/watts/plugins/watts_plugin_rcauth/plugin/rcauth/
 service.RCauth_plugin.plugin.prefix                    = WaTTS   
 service.RCauth_plugin.plugin.client_id                 = <OIDC client ID>
 service.RCauth_plugin.plugin.client_secret_key         = <Key for lookup of client secret in passwordd>
 service.RCauth_plugin.plugin.rcauth_op_entry           = rcauth_plugin
 service.RCauth_plugin.plugin.myproxy_server            = master.data.kit.edu
 service.RCauth_plugin.plugin.myproxy_cert              = /var/lib/watts/.globus/usercert.pem
 service.RCauth_plugin.plugin.myproxy_key               = /var/lib/watts/.globus/decrypted-userkey.pem
 # passwordd keys:                                                          
 service.RCauth_plugin.plugin.myproxy_server_pwd_key_id = myproxy_pwd_key
 service.RCauth_plugin.plugin.proxy_lifetime            = 43200   
 service.RCauth_plugin.plugin.remove_certificate        = True    
```

In principle all config entries ending with '.plugin.' are variables
passed directly to the plugin, while others are variables destined for
Watts.

The ``` service.RCauth_plugin.cmd ``` entries should point to the
rcauth.py file of where you placed the git checkout. 

The non-self-explanatory stuff is as follows: 

- plugin.rcauth_op_entry: This points to a WaTTS openid section that is
  named "rcauth_plugin" in our case.
- client_id and client_secret_key hold the same information that is
  reqpeated in the openid section. This is because they also need to be
  accessible from the plugin.

One known bug with Watts is, that empty lines with whitespaces will cause
the config parser to crash and thereby watts won't start.

# Packaging

Use [indigo-dc/watts-plugin-packager](https://github.com/indigo-dc/watts-plugin-packager) to build Debian / RPM / ArchLinux packages:

```
 $ ./makepkg.sh https://github.com/watts-kit/watts_plugin_rcauth/raw/master/pkg/config.json
```

Note that not all of the packages listed below are available on all targets.
Install manually as needed.


# Dependency Installation and configuration
## Install additional packages

First, (as *root*) get the latest globus deb package, and install the necessary apps:

```
wget http://toolkit.globus.org/ftppub/gt6/installers/repo/globus-toolkit-repo_latest_all.deb

dpkg -i globus-toolkit-repo_latest_all.deb

apt-get update

apt-get install apt-transport-https igtf-policy-classic igtf-policy-iota myproxy globus-proxy-utils python-openssl python-openssl

```
Then, (as *root*) get the needed DEMO CA files:
```
cd /etc/grid-security/certificates/

wget https://ca-pilot.aai.egi.eu/EGISimpleDemoCA.tgz

tar -xvf EGISimpleDemoCA.tgz

rm EGISimpleDemoCA.tgz

```

## Install passwordd
Passwordd is a daemon that stores passwords in memory. Watts makes heavy
use of it, so no OIDC client secrets need to be kept in memore. The
rcauth plugin does the same thing.

https://github.com/watts-kit/passwordd


## Config ##
### Globus ###
Then, as normal user, create **.globus** folder:

```
mkdir $HOME/.globus
```

Place the host grid *certificate* (with the name **usercert.pem**) and *key*
(with the name **userkey.pem**) in the **.globus** folder. Set the right
permissions:
```
chmod 400 userkey.pem
chmod 600 usercert.pem
```

Also, get the latest *trust chain* from the *myproxy server*:
```
myproxy-get-trustroots -s master.data.kit.edu
```
For the configuration of the *rcauth* plugin, check the documentation for the
*watts.conf*.

Also check that the *local time* is set as *Europe/Berlin*, (reboot may be
necessary).
