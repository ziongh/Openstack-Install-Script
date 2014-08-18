Openstack-Install-Script
========================

## Use

This script assumes that you do have a clean install of Ubuntu and it's network interfaces correct configuration.

BEFORE running this script, please open it and edit the initial lines where the variables are dlecared with your own Passwords, and change the network interfaces names as you must (e.g. Web_Interface="eth0").

This install requires 3 network interfaces:

* Web Interface => used by tenants to reach the cloud
* Managment Interface => used to interconnect the cloud
* Tunneling Interface => used to exchange data between VM in tenant network

If the installation is performed through ssh the connection may drop. Requiring the user to continue installation from install_and_configure_dashboard() function. This must be updated!!


## TODO

* Change to use Interfaces instead of IPs
* Configure /etc/network/interface to attach Web Interface IP to br-ex



## Useful commands
### Reboot all openstack Services:
	$ cd /etc/init/; for i in $(ls nova-* | cut -d \. -f 1 | xargs); do sudo service $i restart; done && cd /etc/init/; for i in $(ls neutron-* | cut -d \. -f 1 | xargs); do sudo service $i restart; done && cd /etc/init/; for i in $(ls glance-* | cut -d \. -f 1 | xargs); do sudo service $i restart; done

### Reboot all openstack Neutron Services:
	$ cd /etc/init/; for i in $(ls neutron-* | cut -d \. -f 1 | xargs); do sudo service $i restart; done

### Reboot all openstack Nova Services:
	$ cd /etc/init/; for i in $(ls nova-* | cut -d \. -f 1 | xargs); do sudo service $i restart; done

### Cat all files in a directory recursively:
	$ cd /etc/; for i in $(find . -name "*.*" -print | xargs); do cat $i; done