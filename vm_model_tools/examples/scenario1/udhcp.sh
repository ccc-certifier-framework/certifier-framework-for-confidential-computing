## Install udhcpc script for obtaining & setting IP to interface
$ sudo install -d /mnt/usr/share/udhcpc
$ sudo install examples/udhcp/simple.script /mnt/usr/share/udhcpc/default.script
$ echo "nameserver 8.8.8.8" | sudo tee -a /mnt/etc/resolv.conf # Maybe not
