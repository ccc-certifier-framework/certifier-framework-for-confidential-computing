#!/bin/bash
CMD=$1

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

if [[ "$CMD" == "install" ]]; then
  echo "Installing attestation service..."
  cp attsvc /usr/bin/attsvc
  rm -rf /etc/attsvc
  mkdir /etc/attsvc
  if [[ "$2" == "simulator" ]]; then
    cp attest_key_file.bin /etc/attsvc
    cp example_app.measurement /etc/attsvc
    cp platform_attest_endorsement.bin /etc/attsvc
  fi
  touch /etc/attsvc/config
  echo "# VMware Attestation Service Configuration" >> /etc/attsvc/config
  read -p 'Certifier Service IP: ' host
  echo "certifier_host=$host" >> /etc/attsvc/config
  read -p 'Certifier Service Port: ' host_port
  echo "certifier_port=$host_port" >> /etc/attsvc/config
  read -p 'Notification Client IP: ' client
  echo "client=$client" >> /etc/attsvc/config
  read -p 'Notification Client Port: ' client_port
  echo "client_port=$client_port" >> /etc/attsvc/config
  while true; do
    read -p 'Require Disk Encryption? ' yn
    case $yn in
      [Yy]* ) echo "check_disk=1" >> /etc/attsvc/config; break;;
      [Nn]* ) echo "check_disk=0" >> /etc/attsvc/config; break;;
      * ) echo "Please answer yes or no.";;
    esac
  done

  cp ./attservice.service /etc/systemd/system/attservice.service
  chmod 644 /etc/systemd/system/attservice.service
  systemctl start attservice
  systemctl status attservice
  systemctl enable attservice
elif [[ "$CMD" == "uninstall" ]]; then
  echo "Uninstalling attestation service..."
  systemctl stop attservice
  systemctl disable attservice
  rm /etc/systemd/system/attservice.service
  rm /usr/bin/attsvc
  rm -rf /etc/attsvc
else
  echo "Usage: $0 install|uninstall [simulator]"
fi
