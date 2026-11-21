# Dante Proxy Admin

A lightweight web panel for managing local Linux accounts used by the Dante SOCKS5 server. Create a proxy account, view its password status, lock or unlock its password, and delete the account. The panel uses a separate administrator login and does not need a database.

## Requirements

- A Linux host running Dante with the `username` authentication method, local shadow accounts and standard Linux account management tools. The example targets Ubuntu 24.04 LTS.
- PHP 8.2 or later with sessions and `proc_open`, Python 3, and sudo.
- A dedicated PHP-FPM pool and HTTPS for the admin panel. Limit access to administrators over a private network or VPN.

## Install

1. Install the packages on Ubuntu.

   ```bash
   sudo apt install dante-server php-fpm php-cli python3 sudo
   ```

2. Clone this repository. In the checkout, create the service identity and dedicated group, then install the helper as root.

   ```bash
   sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin dante-web
   sudo groupadd --system dante-proxy-users
   sudo install -m 0755 -o root -g root bin/dante-proxy-admin /usr/local/sbin/dante-proxy-admin
   ```

3. Run `sudo visudo -f /etc/sudoers.d/dante-web` and copy the rule from [`examples/sudoers`](examples/sudoers). Keep the helper and its parent directories writable only by root. Validate the rule and check that the worker can list accounts.

   ```bash
   sudo visudo -c
   printf '%s\n' '{"action":"list"}' |
     sudo -u dante-web /usr/bin/sudo -n /usr/local/sbin/dante-proxy-admin
   ```

4. Deploy `index.php`, `style.css` and `panel.js` to the web root for this panel. Keep the deployed files read-only for the PHP worker. Point your HTTPS web server to a dedicated PHP-FPM pool running as `dante-web`. Set the following pool options, and configure the socket permissions for your web server.

   ```ini
   user = dante-web
   group = dante-web
   env[DANTE_ADMIN_USERNAME] = $DANTE_ADMIN_USERNAME
   env[DANTE_ADMIN_PASSWORD_HASH] = $DANTE_ADMIN_PASSWORD_HASH
   ```

5. Generate the admin hash. Use a unique password of 12–72 bytes. These Bash commands read it without adding it to shell history or passing it as a process argument.

   ```bash
   read -rsp 'New proxy panel administrator password: ' dante_password
   printf '\n'
   printf '%s' "$dante_password" |
     php -r 'echo password_hash(stream_get_contents(STDIN), PASSWORD_DEFAULT), PHP_EOL;'
   unset dante_password
   ```

   Put `DANTE_ADMIN_USERNAME` and `DANTE_ADMIN_PASSWORD_HASH` in the PHP-FPM service environment, for example in a root-owned, mode-`0600` systemd `EnvironmentFile` configured via a service drop-in. Put the hash in single quotes in the environment file to preserve its dollar signs. Restart PHP-FPM after setting or rotating the credentials. Configure your web server to pass the HTTPS request status to PHP and apply a sign-in rate limit.

6. Configure Dante separately. See [`examples/danted.conf`](examples/danted.conf) for a loopback-only TCP proxy that requires membership in `dante-proxy-users`. Set `external` to your host's egress interface and merge the rules into your existing Dante configuration if applicable. Verify and then apply the configuration.

   ```bash
   sudo danted -V -f /etc/danted.conf
   sudo systemctl enable --now danted
   ```

   For an already running service, apply configuration changes with `sudo systemctl restart danted` during a suitable maintenance window.

## Use the panel

1. Sign in with the panel administrator credentials. Create a user such as `proxyteam` with a 12–72 byte password. Passwords cannot contain colons, line breaks or null bytes.
2. For the loopback configuration, open an SSH tunnel from the client using your separate SSH account.

   ```bash
   ssh -N -L 127.0.0.1:1080:127.0.0.1:1080 operator@proxy.example.com
   ```

3. Set the client's SOCKS5 server to `127.0.0.1:1080` with the new proxy credentials. Enable remote DNS resolution if the client supports it.
4. Use **Lock** to prevent new password-authenticated connections, **Unlock** to restore access, or **Delete** to remove the managed account. Existing connections may stay open. Account changes use the live local password database and require no Dante reload.

SOCKS5 username/password authentication sends credentials in cleartext inside the SOCKS connection. Keep the listener on loopback behind SSH, or restrict it to an encrypted private network. The admin panel's HTTPS and the SOCKS connection are separate.

## Upgrade from the original panel

Take the panel offline, back up your Dante configuration and remove the previous web worker's direct sudo rules for system account tools and `systemctl`. Install the new helper and configure the administrator login. The panel only lists local, non-root `proxy…` accounts with `/bin/false` as their shell and `dante-proxy-users` as their primary group. Review existing proxy-only accounts before adopting them individually, for example with `sudo usermod -g dante-proxy-users proxyteam`. Leave unrelated system users outside this dedicated group. Check your Dante rules for the group restriction before bringing the panel back online.
