## Installing necessary packages

First, (as *root*) get the latest globus deb package, and install the necessary apps:

```
wget http://toolkit.globus.org/ftppub/gt6/installers/repo/globus-toolkit-repo_latest_all.deb

dpkg -i globus-toolkit-repo_latest_all.deb

apt-get update

apt-get install apt-transport-https

apt-get install igtf-policy-classic igtf-policy-iota

apt-get install myproxy

apt-get install globus-proxy-utils

```
Then, (as *root*) get the needed DEMO CA files:

```
cd /etc/grid-security/certificates/

wget https://ca-pilot.aai.egi.eu/EGISimpleDemoCA.tgz

tar -xvf EGISimpleDemoCA.tgz

rm EGISimpleDemoCA.tgz

```
Also install the **pyopenssl** (as *root*):

```
apt-get install python-openssl

```

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
For the configuration of the *capilot* plugin, check the documentation for the
*watts.conf*.

Also check that the *local time* is set as *Europe/Berlin*, (reboot may be
necessary).


