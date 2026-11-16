## Install udhcpc script for obtaining & setting IP to interface
$ sudo install -d /mnt/usr/share/udhcpc
$ sudo install examples/udhcp/simple.script /mnt/usr/share/udhcpc/default.script
$ echo "nameserver 8.8.8.8" | sudo tee -a /mnt/etc/resolv.conf # Maybe not

#!/bin/sh
# Currently, we only dispatch according to command.  However, a more
# elaborate system might dispatch by command and interface or do some
# common initialization first, especially if more dhcp event notifications
# are added.

exec /usr/share/udhcpc/sample.$1
