# danted-proxy-admin
Admin panel for dante-server socks proxy
# How to install & configure
1. Setup webserver and php
2. Put index.php script into your published web folder
3. Make sure it has access to your dante-server config file (/etc/danted.conf)
4. Need to add www-data (or additionally created) user to sudoers. Better to make it with help of separate file within /etc/sudoers.d/dante-web
5. Put following line inside our dante-web file: www-data ALL=NOPASSWD: /usr/sbin/useradd, /usr/sbin/userdel, /usr/sbin/usermod, /usr/bin/passwd, /usr/bin/chpasswd, /bin/systemctl reload danted
6. Use following config for danted.conf file:
logoutput: syslog
user.privileged: root
user.unprivileged: nobody

# The listening network interface or address.
internal: 0.0.0.0 port=1089

# The proxying network interface or address.
external: eth0

# socks-rules determine what is proxied through the external interface.
socksmethod: username

# client-rules determine who can connect to the internal interface.
clientmethod: none

client pass {
from: 0.0.0.0/0 to: 0.0.0.0/0
}

socks pass {
from: 0.0.0.0/0 to: 0.0.0.0/0
socksmethod: username
}
