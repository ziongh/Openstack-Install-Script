#! /usr/bin/python

#=================================================================================
#======================= Openstack Installation Script ===========================
#=================================================================================
#*********************************************************************************
#*    Title: Openstack-Istallation-Script
#*    Author: Rodrigo Riskalla Leal
#*    Date: 2014/8/18
#*    Availability: https://github.com/romilgupta/openstack-icehouse-scripts
#*
#*********************************************************************************




#=================================================================================
#======================= Special Thanks to Romil Gupta ===========================
#=================================================================================
#*********************************************************************************
#*    Title: openstack-icehouse-scripts
#*    Author: Gupta, R
#*    Date: 2014/4/29
#*    Availability: https://github.com/romilgupta/openstack-icehouse-scripts
#*
#*********************************************************************************



# This Script is an Enhancement over Romil Gupta great script to install Openstack
# It uses Gupta's functions and is based on Openstack official install guide:
# http://docs.openstack.org/icehouse/install-guide/install/apt/content/index.html
#
# I've tried to follow the order in which commands appear in the given guide,
# however for practical reasons, some of them may appear in different postions,
# and others for some mistake of mine.


import sys
import os
import time
import fcntl
import struct
import socket
import subprocess

# These are module names which are not installed by default.
# These modules will be loaded later after downloading
iniparse = None
psutil = None


#=================================================================================
#============================ Variable Declaration ===============================
#=================================================================================
NEUTRON_PASS = "NEUTRON_PASS"
NOVA_PASS = "NOVA_PASS"
ADMINTOKEN = "ADMINTOKEN"
RABBIT_PASS = "RABBIT_PASS"
Managment_Interface="eth0"
Tunneling_Interface="eth1"


def kill_process(process_name):
	for proc in psutil.process_iter():
		if proc.name == process_name:
			proc.kill()


def delete_file(file_path):
	if os.path.isfile(file_path):
		os.remove(file_path)
	else:
		print("Error: %s file not found" % file_path)

def write_to_file(file_path, content):
	open(file_path, "a").write(content)

def add_to_conf(conf_file, section, param, val):
	config = iniparse.ConfigParser()
	config.readfp(open(conf_file))
	if not config.has_section(section):
		config.add_section(section)
		val += '\n'
	config.set(section, param, val)
	with open(conf_file, 'w') as f:
		config.write(f)


def delete_from_conf(conf_file, section, param):
	config = iniparse.ConfigParser()
	config.readfp(open(conf_file))
	if param is None:
		config.remove_section(section)
	else:
		config.remove_option(section, param)
	with open(conf_file, 'w') as f:
		config.write(f)


def get_from_conf(conf_file, section, param):
	config = iniparse.ConfigParser()
	config.readfp(open(conf_file))
	if param is None:
		raise Exception("parameter missing")
	else:
		return config.get(section, param)

def print_format(string):
	print "+%s+" %("-" * len(string))
	print "|%s|" % string
	print "+%s+" %("-" * len(string))

def execute(command, display=False):
	print_format("Executing : %s" % command)
	process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	if display:
		while True:
			nextline = process.stdout.readline()
			if nextline == '' and process.poll() != None:
				break
			sys.stdout.write(nextline)
			sys.stdout.flush()

		output, stderr = process.communicate()
		exitCode = process.returncode
	else:
		output, stderr = process.communicate()
		exitCode = process.returncode

	if (exitCode == 0):
		return output.strip()
	else:
		print "Error", stderr
		print "Failed to execute command %s" % command
		print exitCode, output
		raise Exception(output)

def get_ip_address(ifname):
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			return socket.inet_ntoa(fcntl.ioctl(s.fileno(),
				0x8915,	 # SIOCGIFADDR
				struct.pack('256s', ifname[:15])
			)[20:24])
		except Exception:
			print "Cannot get IP Address for Interface %s" % ifname
			sys.exit(1)


def initialize_system():
	if not os.geteuid() == 0:
		sys.exit('Please re-run the script with root user')

	execute("apt-get clean" , True)
	execute("apt-get autoclean -y" , True)
	execute("apt-get update -y" , True)
	execute("apt-get install ubuntu-cloud-keyring python-setuptools python-iniparse python-psutil -y", True)
	delete_file("/etc/apt/sources.list.d/icehouse.list")
	execute("echo deb http://ubuntu-cloud.archive.canonical.com/ubuntu precise-updates/icehouse main >> /etc/apt/sources.list.d/icehouse.list")
	execute("apt-get update -y", True)
	execute("apt-get install vlan bridge-utils -y", True)	  
	execute("sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf")

	global iniparse
	if iniparse is None:
		iniparse = __import__('iniparse')

	global psutil
	if psutil is None:
		psutil = __import__('psutil')
		
		
#=================================================================================
#==================	  Components Installation Starts Here ========================
#=================================================================================

my_ip = get_ip_address(Managment_Interface)
tunnel_ip = get_ip_address(Tunneling_Interface)
ip_address = raw_input('Controller IP: ')
ip_address_mgnt= raw_input('Controller Mgmt IP: ')

def install_mysql():
	execute("apt-get install python-mysqldb -y",True)

def install_and_configure_ntp():
	execute("apt-get install ntp -y")
	execute("sed -i 's/server 0.ubuntu.pool.ntp.org/#server 0.ubuntu.pool.ntp.org/g' /etc/ntp.conf")
	execute("sed -i 's/server 1.ubuntu.pool.ntp.org/#server 1.ubuntu.pool.ntp.org/g' /etc/ntp.conf")
	execute("sed -i 's/server 2.ubuntu.pool.ntp.org/#server 2.ubuntu.pool.ntp.org/g' /etc/ntp.conf")
	execute("sed -i 's/server 3.ubuntu.pool.ntp.org/#server 3.ubuntu.pool.ntp.org/g' /etc/ntp.conf")
	execute("sed -i 's/server ntp.ubuntu.com/server %s/g' /etc/ntp.conf" %ip_address_mgnt)
	execute("service ntp restart", True)	

def install_and_configure_nova():
	nova_conf = "/etc/nova/nova.conf"
	nova_paste_conf = "/etc/nova/api-paste.ini"
	nova_compute_conf = "/etc/nova/nova-compute.conf"

	execute("apt-get install qemu-kvm libvirt-bin python-libvirt python-novaclient -y", True)
	execute("apt-get install nova-compute-kvm novnc python-guestfs -y", True)

	execute("dpkg-statoverride	--update --add root root 0644 /boot/vmlinuz-$(uname -r)", True)

	execute("touch /etc/kernel/postinst.d/statoverride",True)

	write_to_file("/etc/kernel/postinst.d/statoverride", "#!/bin/sh\n")
	write_to_file("/etc/kernel/postinst.d/statoverride", "version=\"$1\"\n")
	write_to_file("/etc/kernel/postinst.d/statoverride", "# passing the kernel version is required\n")
	write_to_file("/etc/kernel/postinst.d/statoverride", "[ -z \"${version}\" ] && exit 0\n")
	write_to_file("/etc/kernel/postinst.d/statoverride", "dpkg-statoverride --update --add root root 0644 /boot/vmlinuz-${version}\n")

	execute("chmod +x /etc/kernel/postinst.d/statoverride")

	add_to_conf(nova_conf, "DEFAULT", "auth_strategy", "keystone")
	add_to_conf(nova_conf, "database", "connection", "mysql://nova:%s@%s/nova" %(NOVA_PASS,ip_address_mgnt))

	add_to_conf(nova_conf, "keystone_authtoken", "auth_uri", "http://%s:5000/v2.0" %ip_address_mgnt)
	add_to_conf(nova_conf, "keystone_authtoken", "auth_host", ip_address_mgnt)
	add_to_conf(nova_conf, "keystone_authtoken", "auth_port", "35357")
	add_to_conf(nova_conf, "keystone_authtoken", "auth_protocol", "http")
	add_to_conf(nova_conf, "keystone_authtoken", "admin_tenant_name", "service")
	add_to_conf(nova_conf, "keystone_authtoken", "admin_user", "nova")
	add_to_conf(nova_conf, "keystone_authtoken", "admin_password ", NOVA_PASS)

	add_to_conf(nova_conf, "DEFAULT", "rpc_backend", "rabbit")
	add_to_conf(nova_conf, "DEFAULT", "rabbit_host", ip_address_mgnt)
	add_to_conf(nova_conf, "DEFAULT", "rabbit_password", RABBIT_PASS)

	add_to_conf(nova_conf, "DEFAULT", "my_ip", my_ip)
	add_to_conf(nova_conf, "DEFAULT", "vnc_enabled", "True")
	add_to_conf(nova_conf, "DEFAULT", "vncserver_listen", "0.0.0.0")
	add_to_conf(nova_conf, "DEFAULT", "vncserver_proxyclient_address", my_ip)
	add_to_conf(nova_conf, "DEFAULT", "novncproxy_base_url", "http://%s:6080/vnc_auto.html" %ip_address)

	add_to_conf(nova_conf, "DEFAULT", "glance_host", ip_address_mgnt)

	try:
		execute("rm /var/lib/nova/nova.sqlite",True)
	except Exception:
		print "Already deleted file"

	add_to_conf(nova_conf, "DEFAULT", "logdir", "/var/log/nova")
	add_to_conf(nova_conf, "DEFAULT", "verbose", "True")
	add_to_conf(nova_conf, "DEFAULT", "debug", "True")
	add_to_conf(nova_conf, "DEFAULT", "lock_path", "/var/lib/nova")
	add_to_conf(nova_conf, "DEFAULT", "compute_driver", "libvirt.LibvirtDriver")
	add_to_conf(nova_conf, "DEFAULT", "dhcpbridge_flagfile", "/etc/nova/nova.conf")

	add_to_conf(nova_conf, "DEFAULT", "network_api_class", "nova.network.neutronv2.api.API")
	add_to_conf(nova_conf, "DEFAULT", "neutron_url", "http://%s:9696"%ip_address_mgnt)
	add_to_conf(nova_conf, "DEFAULT", "neutron_auth_strategy", "keystone")
	add_to_conf(nova_conf, "DEFAULT", "neutron_admin_tenant_name", "service")
	add_to_conf(nova_conf, "DEFAULT", "neutron_admin_username", "neutron")
	add_to_conf(nova_conf, "DEFAULT", "neutron_admin_password", NEUTRON_PASS)
	add_to_conf(nova_conf, "DEFAULT", "neutron_admin_auth_url", "http://%s:35357/v2.0"%ip_address_mgnt)
	add_to_conf(nova_conf, "DEFAULT", "linuxnet_interface_driver", "nova.network.linux_net.LinuxOVSInterfaceDriver")
	add_to_conf(nova_conf, "DEFAULT", "firewall_driver", "nova.virt.firewall.NoopFirewallDriver")
	add_to_conf(nova_conf, "DEFAULT", "security_group_api", "neutron")



	add_to_conf(nova_conf, "DEFAULT", "novnc_enabled", "true")
	add_to_conf(nova_conf, "DEFAULT", "novncproxy_port", "6080")
   
	add_to_conf(nova_compute_conf, "DEFAULT", "libvirt_type", "qemu")

	execute("service libvirt-bin restart", True)
	execute("service nova-compute restart", True)
	time.sleep(2)


def install_and_configure_ovs():
	neutron_conf = "/etc/neutron/neutron.conf"
	neutron_paste_conf = "/etc/neutron/api-paste.ini"
	neutron_plugin_conf = "/etc/neutron/plugins/ml2/ml2_conf.ini" 

	execute("sed -i 's/#net.ipv4.conf.default.rp_filter=1/net.ipv4.conf.default.rp_filter=0/g' /etc/sysctl.conf",True)
	execute("sed -i 's/#net.ipv4.conf.all.rp_filter=1/net.ipv4.conf.all.rp_filter=0/g' /etc/sysctl.conf",True)

	execute("sysctl -p",True)
	
	execute("apt-get install neutron-common neutron-plugin-ml2 neutron-plugin-openvswitch-agent openvswitch-datapath-dkms -y",True)

	add_to_conf(neutron_conf, "DEFAULT", "auth_strategy", "keystone")

	add_to_conf(neutron_conf, "keystone_authtoken", "auth_uri", "http://%s:5000/v2.0" %ip_address_mgnt)
	add_to_conf(neutron_conf, "keystone_authtoken", "auth_host", ip_address_mgnt)
	add_to_conf(neutron_conf, "keystone_authtoken", "auth_port", "35357")
	add_to_conf(neutron_conf, "keystone_authtoken", "auth_protocol", "http")
	add_to_conf(neutron_conf, "keystone_authtoken", "admin_tenant_name", "service")
	add_to_conf(neutron_conf, "keystone_authtoken", "admin_user", "neutron")
	add_to_conf(neutron_conf, "keystone_authtoken", "admin_password ", NEUTRON_PASS)

	add_to_conf(neutron_conf, "DEFAULT", "agent_down_time  ", "75")	
	add_to_conf(neutron_conf, "DEFAULT", "report_interval ", "30")	


	add_to_conf(neutron_conf, "DEFAULT", "bind_host", ip_address_mgnt)

	add_to_conf(neutron_conf, "DEFAULT", "rpc_backend", "neutron.openstack.common.rpc.impl_kombu")
	add_to_conf(neutron_conf, "DEFAULT", "rabbit_host", ip_address_mgnt)
	add_to_conf(neutron_conf, "DEFAULT", "rabbit_password", RABBIT_PASS)

	add_to_conf(neutron_conf, "DEFAULT", "core_plugin", "ml2")
	add_to_conf(neutron_conf, "DEFAULT", "service_plugins", "router")
	add_to_conf(neutron_conf, "DEFAULT", "allow_overlapping_ips", "True")


	add_to_conf(neutron_conf, "DEFAULT", "verbose", "True")
	add_to_conf(neutron_conf, "DEFAULT", "debug", "True")

	add_to_conf(neutron_plugin_conf, "ml2", "type_drivers", "gre")
	add_to_conf(neutron_plugin_conf, "ml2", "tenant_network_types", "gre")
	add_to_conf(neutron_plugin_conf, "ml2", "mechanism_drivers", "openvswitch")

	add_to_conf(neutron_plugin_conf, "ml2_type_gre", "tunnel_id_ranges", "1:1000")

	add_to_conf(neutron_plugin_conf, "securitygroup", "firewall_driver", "neutron.agent.linux.iptables_firewall.OVSHybridIptablesFirewallDriver")
	add_to_conf(neutron_plugin_conf, "securitygroup", "enable_security_group", "True")

	add_to_conf(neutron_plugin_conf, "OVS", "tunnel_types", "gre")
	add_to_conf(neutron_plugin_conf, "OVS", "enable_tunneling", "True")
	add_to_conf(neutron_plugin_conf, "OVS", "local_ip", tunnel_ip)

	execute("service neutron-plugin-openvswitch-agent restart", True)
	execute("service openvswitch-switch restart", True)
	time.sleep(2)
	execute("ovs-vsctl --may-exist add-br br-int",True)
   

initialize_system()
install_mysql()
install_and_configure_ntp()
install_and_configure_nova()
install_and_configure_ovs()


