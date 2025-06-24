# danted-proxy-admin
Admin panel for dante-server socks proxy
# How to install & configure
1. Setup webserver and php
2. Put index.php script into your published web folder
3. Make sure it has access to your dante-server config file (/etc/danted.conf)
4. Need to add www-data (or additionally created) user to sudoers. Better to make it with help of separate file within /etc/sudoers.d/dante-web
5. Put following line inside our dante-web file: www-data ALL=NOPASSWD: /usr/sbin/useradd, /usr/sbin/userdel, /usr/sbin/usermod, /usr/bin/passwd, /usr/bin/chpasswd, /bin/systemctl reload danted
6. Use following config for danted.conf file:

```
logoutput: syslog
user.privileged: root
user.unprivileged: nobody
internal: 0.0.0.0 port=1089
external: eth0
socksmethod: username
clientmethod: none
client pass {
from: 0.0.0.0/0 to: 0.0.0.0/0
}
socks pass {
from: 0.0.0.0/0 to: 0.0.0.0/0
socksmethod: username
}
```
![image](https://github.com/user-attachments/assets/ff60e996-51aa-40f9-9951-d52556dc3eb9)
