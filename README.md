# 389-ds Audit Log Bridge to Graylog

This script reads the audit log generated by [389-ds], converts it to [GELF] and sends it to a [Graylog] server.

[389-ds]: https://directory.fedoraproject.org/
[GELF]: https://docs.graylog.org/en/2.4/pages/gelf.html
[Graylog]: https://www.graylog.org/

## Installation

1. Clone this repository into `/opt/dirsrv-audit-graylog-bridge`:

       git clone https://github.com/PLUTEX/dirsrv-audit-graylog-bridge

2. Configure your Graylog server in the file `/etc/default/dirsrv-audit-graylog-bridge`:

       GRAYLOG_HOST="graylog.example.org"
       GRAYLOG_PORT=12201

3. Symlink the systemd unit files:

       ln -s /opt/dirsrv-audit-graylog-bridge/dirsrv-audit-graylog-bridge@.{socket,service} /etc/systemd/system/

4. Enable the systemd unit files (with the same instance name as your `dirsrv@.service` unit, we assume "ldap"):

       systemctl enable dirsrv-audit-graylog-bridge@ldap.{service.socket}

5. Optionally, add a `BindsTo=` dependency to the `dirsrv@.service` unit itself:

       systemctl edit dirsrv@.service
       [Unit]
       BindsTo=dirsrv-audit-graylog-bridge@%i.socket