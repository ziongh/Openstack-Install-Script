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
pexpect = None
netaddr = None
pip = None


#=================================================================================
#============================ Variable Declaration ===============================
#=================================================================================
ADMINTOKEN = "ADMINTOKEN"
KEYSTONE_DBPASS = "KEYSTONE_DBPASS"
mysql_password = "mysql_password"
ADMIN_TENANT_PASS = "ADMIN_TENANT_PASS"
GLANCE_PASS = "GLANCE_PASS"
NEUTRON_PASS = "NEUTRON_PASS"
NOVA_PASS = "NOVA_PASS"
RABBIT_PASS = "RABBIT_PASS"
Web_Interface="eth0"
Managment_Interface="eth1"
Tunneling_Interface="eth2"



service_tenant = None

def kill_process(process_name):
	for proc in psutil.process_iter():
		if proc.name == process_name:
			proc.kill()

def get_netmask(ifname):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x891b, struct.pack('256s',ifname))[20:24])
	except Exception:
		print "Cannot get IP Address for Interface %s" % ifname
		sys.exit(1)

def get_default_gateway_linux():
	"""Read the default gateway directly from /proc."""
	with open("/proc/net/route") as fh:
		for line in fh:
			fields = line.strip().split()
			if fields[1] != '00000000' or not int(fields[3], 16) & 2:
				continue
			return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

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


def execute_db_commnads(command):
	cmd = """mysql -uroot -p%s -e "%s" """ % (mysql_password, command)
	output = execute(cmd)
	return output


def initialize_system():
	if not os.geteuid() == 0:
		sys.exit('Please re-run the script with root user')

	#iuyiuiyui = raw_input('before Initialize system...')
	execute("apt-get clean" , True)
	execute("apt-get autoclean -y" , True)
	execute("apt-get update -y" , True)
	execute("apt-get install ethtool expect ubuntu-cloud-keyring python-setuptools python-iniparse python-psutil python-pip python-netaddr -y", True)
	delete_file("/etc/apt/sources.list.d/icehouse.list")
	execute("echo deb http://ubuntu-cloud.archive.canonical.com/ubuntu precise-updates/icehouse main >> /etc/apt/sources.list.d/icehouse.list")
	execute("apt-get update -y", True)
	execute("apt-get install vlan bridge-utils -y", True)
	execute("sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf")
	execute("sysctl -p",True)

	#iuyiuiyui = raw_input('before Initializ imports...')

	global iniparse
	if iniparse is None:
		iniparse = __import__('iniparse')

	global psutil
	if psutil is None:
		psutil = __import__('psutil')

	global pip
	if pip is None:
		pip = __import__('pip')
	
	pip.main(['install', 'pexpect'])
	
	global pexpect
	if pexpect is None:
		pexpect = __import__('pexpect')

	global netaddr
	if netaddr is None:
		netaddr = __import__('netaddr')
		
		
		
		
#=================================================================================
#==================	  Components Installation Starts Here ========================
#=================================================================================

#iuyiuiyui = raw_input('getting IPs...')
ip_address = get_ip_address(Web_Interface)
ip_address_mgnt = get_ip_address(Managment_Interface)
ip_address_tunneling = get_ip_address(Tunneling_Interface)

ip_address_gateway = get_default_gateway_linux()

ip_mask = get_netmask(Web_Interface)
ip_mask_mgnt = get_netmask(Managment_Interface)

def install_and_configure_ntp():
	execute("apt-get install ntp -y")
	execute("sed -i 's/server 0.ubuntu.pool.ntp.org/#server 0.ubuntu.pool.ntp.org/g' /etc/ntp.conf")
	execute("sed -i 's/server 1.ubuntu.pool.ntp.org/#server 1.ubuntu.pool.ntp.org/g' /etc/ntp.conf")
	execute("sed -i 's/server 2.ubuntu.pool.ntp.org/#server 2.ubuntu.pool.ntp.org/g' /etc/ntp.conf")
	execute("sed -i 's/server 3.ubuntu.pool.ntp.org/#server 3.ubuntu.pool.ntp.org/g' /etc/ntp.conf")
	execute("sed -i 's/server ntp.ubuntu.com/server %s/g' /etc/ntp.conf" %ip_address_mgnt)
	execute("service ntp restart", True)


def install_rabbitmq():
	execute("apt-get install rabbitmq-server -y", True)

	execute("rabbitmqctl change_password guest %s" %RABBIT_PASS, True)

	execute("service rabbitmq-server restart", True)
	time.sleep(2)
	#iuyiuiyui = raw_input('Rabbit intalled!')


def install_database():
	mysql_conf = "/etc/mysql/my.cnf"

	os.environ['DEBIAN_FRONTEND'] = 'noninteractive'
	execute("apt-get install mysql-server python-mysqldb -y", True)
	newLine = "bind-address = %s\ndefault-storage-engine = innodb\ninnodb_file_per_table\ncollation-server = utf8_general_ci\ninit-connect = 'SET NAMES utf8'\ncharacter-set-server = utf8\n" %ip_address_mgnt

	execute("cp /etc/mysql/my.cnf /etc/mysql/my.cnf.bk")

	f1 = open('/etc/mysql/my.cnf', 'r')
	lines = f1.readlines()
	origLine = ""
	for line in lines:
		if "bind-address" in line:
			origLine = line
			break

	f1.close()

	f2 = open('/etc/mysql/my.cnf', 'w')
	for line in lines:
		if origLine != line:
			f2.write(line)
		else:
			f2.write(newLine)
	f2.close()

	#iuyiuiyui = raw_input('Editted Mysql...')

	execute("service mysql restart", True)
	time.sleep(2)
	execute("mysql_install_db", True)

	child = pexpect.spawn('mysql_secure_installation')
	child.expect('Enter current password for root')
	child.sendline ('')

	child.expect('Set root password')
	child.sendline ('y')

	child.expect('New password')
	child.sendline (mysql_password)

	child.expect('Re-enter new password')
	child.sendline (mysql_password)

	child.expect('Remove anonymous users')
	child.sendline ('y')

	child.expect('Disallow root login remotely')
	child.sendline ('y')

	child.expect('Remove test database and access to it')
	child.sendline ('y')

	child.expect('Reload privilege tables now')
	child.sendline ('y')

	print child.before
	child.interact()
	

	try:
		execute("mysqladmin -u root password %s" % mysql_password)
	except Exception:
		print " Mysql Password already set as : %s " % mysql_password


def install_and_configure_keystone():
	keystone_conf = "/etc/keystone/keystone.conf"

	execute_db_commnads("DROP DATABASE IF EXISTS keystone;")
	execute_db_commnads("CREATE DATABASE keystone;")
	execute_db_commnads("GRANT ALL PRIVILEGES ON keystone.* TO 'keystone'@'%%' IDENTIFIED BY '%s';" %KEYSTONE_DBPASS)
	execute_db_commnads("GRANT ALL PRIVILEGES ON keystone.* TO 'keystone'@'localhost' IDENTIFIED BY '%s';" %KEYSTONE_DBPASS)

	#iuyiuiyui = raw_input('CreatedSQL database Keystone...')


	execute("apt-get install keystone -y", True)

	try:
		execute("rm /var/lib/keystone/keystone.db", True)
	except Exception:
		print "Already deleted file"

	add_to_conf(keystone_conf, "database", "connection", "mysql://keystone:%s@localhost/keystone" %KEYSTONE_DBPASS)
	add_to_conf(keystone_conf, "DEFAULT", "admin_token", ADMINTOKEN)
	add_to_conf(keystone_conf, "DEFAULT", "admin_port", 35357)
	add_to_conf(keystone_conf, "DEFAULT", "log_dir", "/var/log/keystone")


	#add_to_conf(keystone_conf, "DEFAULT", "bind_host ", ip_address_mgnt)
	
	
	add_to_conf(keystone_conf, "signing", "token_format", "UUID")

	execute("service keystone restart", True)

	time.sleep(3)

	execute("keystone-manage db_sync")

	#iuyiuiyui = raw_input('CreatedSQL tables Keystone...')


	execute("service keystone restart", True)

	time.sleep(3)

def create_keystone_users():
	os.environ['SERVICE_TOKEN'] = ADMINTOKEN
	os.environ['SERVICE_ENDPOINT'] = 'http://%s:35357/v2.0'% ip_address_mgnt
	os.environ['no_proxy'] = "localhost,127.0.0.1,%s" % ip_address
	global service_tenant 
	
	#TODO(ish) : This is crude way of doing. Install keystone client and use that to create tenants, role etc
	

	admin_tenant = execute("keystone tenant-create --name admin --description 'Admin Tenant' --enabled true | grep ' id '| awk '{print $4}'")
	admin_user = execute("keystone user-create --tenant_id %s --name admin --pass %s --enabled true | grep ' id '|awk '{print $4}'" % (admin_tenant,ADMIN_TENANT_PASS))
	admin_role = execute("keystone role-create --name admin|grep ' id ' | awk '{print $4}'")
	execute("keystone user-role-add --user=admin --tenant=admin --role=admin")
	#execute("keystone user-role-add --user=admin --role=_member_ --tenant=admin")
	#execute("keystone user-role-add --user %s --tenant %s --role %s" % (admin_user, admin_tenant, admin_role))
	#iuyiuiyui = raw_input('Created Keystone user admin...')


	service_tenant = execute("keystone tenant-create --name service --description 'Service Tenant' --enabled true |grep ' id '|awk '{print $4}'")
	#iuyiuiyui = raw_input('Created Keystone user service...')


	#keystone
	keystone_service = execute("keystone service-create --name=keystone --type=identity --description='Keystone Identity Service'|grep ' id '|awk '{print $4}'")
	execute("keystone endpoint-create --region region --service_id=%s --publicurl=http://%s:5000/v2.0 --internalurl=http://%s:5000/v2.0 --adminurl=http://%s:35357/v2.0" % (keystone_service, ip_address,ip_address_mgnt,ip_address_mgnt))
	#iuyiuiyui = raw_input('Created Keystone service Keystone...')


	#Glance
	glance_user = execute("keystone user-create --tenant_id %s --name glance --pass %s --enabled true|grep ' id '|awk '{print $4}'" % (service_tenant,GLANCE_PASS))
	execute("keystone user-role-add --user_id %s --tenant_id %s --role_id %s" % (glance_user, service_tenant, admin_role))

	glance_service = execute("keystone service-create --name=glance --type=image --description='Glance Image Service'|grep ' id '|awk '{print $4}'")
	execute("keystone endpoint-create --region region --service_id=%s --publicurl=http://%s:9292 --internalurl=http://%s:9292 --adminurl=http://%s:9292" % (glance_service, ip_address,ip_address_mgnt,ip_address_mgnt))
	#iuyiuiyui = raw_input('Created Keystone service Glance...')


	#nova
	nova_user = execute("keystone user-create --tenant_id %s --name nova --pass %s --enabled true|grep ' id '|awk '{print $4}'" % (service_tenant,NOVA_PASS))
	execute("keystone user-role-add --user_id %s --tenant_id %s --role_id %s" % (nova_user, service_tenant, admin_role))

	nova_service = execute("keystone service-create --name=nova --type=compute --description='Nova Compute Service'|grep ' id '|awk '{print $4}'")
	execute("keystone endpoint-create --region region --service_id=%s --publicurl='http://%s:8774/v2/%%(tenant_id)s' --internalurl='http://%s:8774/v2/%%(tenant_id)s' --adminurl='http://%s:8774/v2/%%(tenant_id)s'" % (nova_service, ip_address,ip_address_mgnt,ip_address_mgnt))
	#iuyiuiyui = raw_input('Created Keystone service Nova...')


	#neutron
	neutron_user = execute("keystone user-create --tenant_id %s --name neutron --pass %s --enabled true|grep ' id '|awk '{print $4}'" % (service_tenant,NEUTRON_PASS))
	execute("keystone user-role-add --user_id %s --tenant_id %s --role_id %s" % (neutron_user, service_tenant, admin_role))

	neutron_service = execute("keystone service-create --name=neutron --type=network  --description='OpenStack Networking service'|grep ' id '|awk '{print $4}'")
	#iuyiuiyui = raw_input('Created Keystone service Glance...')
	execute("keystone endpoint-create --region region --service_id=%s --publicurl=http://%s:9696 --internalurl=http://%s:9696 --adminurl=http://%s:9696" % (neutron_service, ip_address,ip_address_mgnt,ip_address_mgnt),True)
	#iuyiuiyui = raw_input('Created Keystone service Neutron...')


	#write a rc file
	adminrc = "/root/adminrc"
	delete_file(adminrc)
	write_to_file(adminrc, "export OS_USERNAME=admin\n")
	write_to_file(adminrc, "export OS_PASSWORD=%s\n" %ADMIN_TENANT_PASS)
	write_to_file(adminrc, "export OS_TENANT_NAME=admin\n")
	write_to_file(adminrc, "export OS_AUTH_URL=http://%s:5000/v2.0\n" %ip_address_mgnt)

	#iuyiuiyui = raw_input('Istalled Keystone and Created file adminrc...')


def install_command_line():
	execute("apt-get install python-novaclient -y",True)

def install_and_configure_glance():
	glance_api_conf = "/etc/glance/glance-api.conf"
	glance_registry_conf = "/etc/glance/glance-registry.conf"
	glance_api_paste_conf = "/etc/glance/glance-api-paste.ini"
	glance_registry_paste_conf = "/etc/glance/glance-registry-paste.ini"

	execute_db_commnads("DROP DATABASE IF EXISTS glance;")
	execute_db_commnads("CREATE DATABASE glance;")
	execute_db_commnads("GRANT ALL PRIVILEGES ON glance.* TO 'glance'@'%%' IDENTIFIED BY '%s';" %GLANCE_PASS)
	execute_db_commnads("GRANT ALL PRIVILEGES ON glance.* TO 'glance'@'localhost' IDENTIFIED BY '%s';" %GLANCE_PASS)

	#iuyiuiyui = raw_input('Created SQL databse Glance')


	execute("apt-get install glance python-glanceclient -y", True)


	#add_to_conf(glance_api_paste_conf, "filter:authtoken", "auth_host", ip_address_mgnt)
	#add_to_conf(glance_api_paste_conf, "filter:authtoken", "auth_port", "35357")
	#add_to_conf(glance_api_paste_conf, "filter:authtoken", "auth_protocol", "http")
	#add_to_conf(glance_api_paste_conf, "filter:authtoken", "admin_tenant_name", "service")
	#add_to_conf(glance_api_paste_conf, "filter:authtoken", "admin_user", "glance")
	#add_to_conf(glance_api_paste_conf, "filter:authtoken", "admin_password", GLANCE_PASS)


	#add_to_conf(glance_registry_paste_conf, "filter:authtoken", "auth_host", ip_address_mgnt)
	#add_to_conf(glance_registry_paste_conf, "filter:authtoken", "auth_port", "35357")
	#add_to_conf(glance_registry_paste_conf, "filter:authtoken", "auth_protocol", "http")
	#add_to_conf(glance_registry_paste_conf, "filter:authtoken", "admin_tenant_name", "service")
	#add_to_conf(glance_registry_paste_conf, "filter:authtoken", "admin_user", "glance")
	#add_to_conf(glance_registry_paste_conf, "filter:authtoken", "admin_password", GLANCE_PASS)


	add_to_conf(glance_api_conf, "database", "connection", "mysql://glance:%s@localhost/glance" %GLANCE_PASS)
	add_to_conf(glance_registry_conf, "database", "connection", "mysql://glance:%s@localhost/glance" %GLANCE_PASS)

	add_to_conf(glance_api_conf, "DEFAULT", "verbose", "true")
	add_to_conf(glance_api_conf, "DEFAULT", "debug", "true")

	#add_to_conf(glance_api_conf, "DEFAULT", "bind_host", ip_address_mgnt)
	add_to_conf(glance_api_conf, "DEFAULT", "registry_host", ip_address_mgnt)

	delete_from_conf(glance_api_conf,"database","sqlite_db")

	add_to_conf(glance_registry_conf, "DEFAULT", "verbose", "true")
	add_to_conf(glance_registry_conf, "DEFAULT", "debug", "true")

	#add_to_conf(glance_registry_conf, "DEFAULT", "bind_host", ip_address_mgnt)

	add_to_conf(glance_api_conf, "DEFAULT", "rpc_backend", "rabbit")
	add_to_conf(glance_api_conf, "DEFAULT", "rabbit_host", ip_address_mgnt)
	add_to_conf(glance_api_conf, "DEFAULT", "rabbit_password", RABBIT_PASS)

	add_to_conf(glance_api_conf, "keystone_authtoken", "auth_uri", "http://%s:5000/v2.0" %ip_address_mgnt)
	add_to_conf(glance_api_conf, "keystone_authtoken", "auth_host", ip_address_mgnt)
	add_to_conf(glance_api_conf, "keystone_authtoken", "auth_port", "35357")
	add_to_conf(glance_api_conf, "keystone_authtoken", "auth_protocol", "http")
	add_to_conf(glance_api_conf, "keystone_authtoken", "admin_tenant_name", "service")
	add_to_conf(glance_api_conf, "keystone_authtoken", "admin_user", "glance")
	add_to_conf(glance_api_conf, "keystone_authtoken", "admin_password ", GLANCE_PASS)
	add_to_conf(glance_api_conf, "paste_deploy", "flavor ", "keystone")

	add_to_conf(glance_registry_conf, "keystone_authtoken", "auth_uri", "http://%s:5000/v2.0" %ip_address_mgnt)
	add_to_conf(glance_registry_conf, "keystone_authtoken", "auth_host", ip_address_mgnt)
	add_to_conf(glance_registry_conf, "keystone_authtoken", "auth_port", "35357")
	add_to_conf(glance_registry_conf, "keystone_authtoken", "auth_protocol", "http")
	add_to_conf(glance_registry_conf, "keystone_authtoken", "admin_tenant_name", "service")
	add_to_conf(glance_registry_conf, "keystone_authtoken", "admin_user", "glance")
	add_to_conf(glance_registry_conf, "keystone_authtoken", "admin_password ", GLANCE_PASS)
	add_to_conf(glance_registry_conf, "paste_deploy", "flavor ", "keystone")


	
	try:
		execute("rm /var/lib/glance/glance.sqlite",True)
	except Exception:
		print "Already deleted file"

	
	execute("glance-manage db_sync")
	#iuyiuiyui = raw_input('Created SQL tables Glance')


	execute("service glance-registry restart", True)
	execute("service glance-api restart", True)
	time.sleep(2)
	#iuyiuiyui = raw_input('Installed Glance')

	




def install_and_configure_nova():
	nova_conf = "/etc/nova/nova.conf"
	nova_paste_conf = "/etc/nova/api-paste.ini"
	
	execute_db_commnads("DROP DATABASE IF EXISTS nova;")
	execute_db_commnads("CREATE DATABASE nova;")
	execute_db_commnads("GRANT ALL PRIVILEGES ON nova.* TO 'nova'@'%%' IDENTIFIED BY '%s';" %NOVA_PASS)
	execute_db_commnads("GRANT ALL PRIVILEGES ON nova.* TO 'nova'@'localhost' IDENTIFIED BY '%s';" %NOVA_PASS)
	#iuyiuiyui = raw_input('Created SQL databse Nova')


	execute("apt-get install nova-api nova-cert nova-scheduler nova-conductor novnc nova-consoleauth nova-novncproxy python-novaclient -y", True)


	#add_to_conf(nova_paste_conf, "filter:authtoken", "auth_host", ip_address_mgnt)
	#add_to_conf(nova_paste_conf, "filter:authtoken", "auth_port", "35357")
	#add_to_conf(nova_paste_conf, "filter:authtoken", "auth_protocol", "http")
	#add_to_conf(nova_paste_conf, "filter:authtoken", "admin_tenant_name", "service")
	#add_to_conf(nova_paste_conf, "filter:authtoken", "admin_user", "nova")
	#add_to_conf(nova_paste_conf, "filter:authtoken", "admin_password", NOVA_PASS)

	add_to_conf(nova_conf, "database", "connection", "mysql://nova:%s@localhost/nova" %NOVA_PASS)
	add_to_conf(nova_conf, "DEFAULT", "rpc_backend", "rabbit")
	add_to_conf(nova_conf, "DEFAULT", "rabbit_host", ip_address_mgnt)
	add_to_conf(nova_conf, "DEFAULT", "rabbit_password", RABBIT_PASS)

	add_to_conf(nova_conf, "DEFAULT", "my_ip", ip_address_mgnt)
	add_to_conf(nova_conf, "DEFAULT", "vncserver_listen", ip_address)
	add_to_conf(nova_conf, "DEFAULT", "vncserver_proxyclient_address", ip_address)

	add_to_conf(nova_conf, "DEFAULT", "auth_strategy", "keystone")

	add_to_conf(nova_conf, "keystone_authtoken", "auth_uri", "http://%s:5000/v2.0" %ip_address_mgnt)
	add_to_conf(nova_conf, "keystone_authtoken", "auth_host", ip_address_mgnt)
	add_to_conf(nova_conf, "keystone_authtoken", "auth_port", "35357")
	add_to_conf(nova_conf, "keystone_authtoken", "auth_protocol", "http")
	add_to_conf(nova_conf, "keystone_authtoken", "admin_tenant_name", "service")
	add_to_conf(nova_conf, "keystone_authtoken", "admin_user", "nova")
	add_to_conf(nova_conf, "keystone_authtoken", "admin_password ", NOVA_PASS)

	try:
		execute("rm /var/lib/nova/nova.sqlite", True)
	except Exception:
		print "Already deleted file"

	

	add_to_conf(nova_conf, "DEFAULT", "log_dir", "/var/log/nova")
	#add_to_conf(nova_conf, "DEFAULT", "lock_path", "/var/lib/nova")
	#add_to_conf(nova_conf, "DEFAULT", "root_helper", "sudo nova-rootwrap /etc/nova/rootwrap.conf")
	add_to_conf(nova_conf, "DEFAULT", "verbose", "True")
	add_to_conf(nova_conf, "DEFAULT", "debug", "True")


	#add_to_conf(nova_conf, "DEFAULT", "glance_api_servers", "%s:9292" %ip_address_mgnt)

	#Configure NOVA to use NEUTRON
	add_to_conf(nova_conf, "DEFAULT", "network_api_class", "nova.network.neutronv2.api.API")
	add_to_conf(nova_conf, "DEFAULT", "neutron_url", "http://%s:9696" %ip_address_mgnt)
	add_to_conf(nova_conf, "DEFAULT", "neutron_auth_strategy", "keystone")
	add_to_conf(nova_conf, "DEFAULT", "neutron_admin_tenant_name", "service")
	add_to_conf(nova_conf, "DEFAULT", "neutron_admin_username", "neutron")
	add_to_conf(nova_conf, "DEFAULT", "neutron_admin_password", NEUTRON_PASS)
	add_to_conf(nova_conf, "DEFAULT", "neutron_admin_auth_url", "http://%s:35357/v2.0" %ip_address_mgnt)
	add_to_conf(nova_conf, "DEFAULT", "linuxnet_interface_driver", "nova.network.linux_net.LinuxOVSInterfaceDriver")
	add_to_conf(nova_conf, "DEFAULT", "firewall_driver", "nova.virt.firewall.NoopFirewallDriver")
	add_to_conf(nova_conf, "DEFAULT", "security_group_api", "neutron")

	add_to_conf(nova_conf, "DEFAULT", "service_neutron_metadata_proxy", "true")
	add_to_conf(nova_conf, "DEFAULT", "neutron_metadata_proxy_shared_secret", ADMINTOKEN)



	#add_to_conf(nova_conf, "DEFAULT", "dhcpbridge_flagfile", "/etc/nova/nova.conf")
	#add_to_conf(nova_conf, "DEFAULT", "novnc_enabled", "true")
	#add_to_conf(nova_conf, "DEFAULT", "novncproxy_base_url", "http://%s:6080/vnc_auto.html" % ip_address_mgnt)
	#add_to_conf(nova_conf, "DEFAULT", "novncproxy_port", "6080")
  
	execute("nova-manage db sync")
	#iuyiuiyui = raw_input('Created SQL tables Nova')

	execute("service nova-api restart", True)
	execute("service nova-cert restart", True)
	execute("service nova-scheduler restart", True)
	execute("service nova-conductor restart", True)
	execute("service nova-consoleauth restart", True)
	execute("service nova-novncproxy restart", True)
	time.sleep(2)


def install_and_configure_neutron():
	neutron_conf = "/etc/neutron/neutron.conf"
	neutron_paste_conf = "/etc/neutron/api-paste.ini"
	neutron_plugin_conf = "/etc/neutron/plugins/ml2/ml2_conf.ini"

	execute_db_commnads("DROP DATABASE IF EXISTS neutron;")
	execute_db_commnads("CREATE DATABASE neutron;")
	execute_db_commnads("GRANT ALL PRIVILEGES ON neutron.* TO 'neutron'@'%%' IDENTIFIED BY '%s';" %NEUTRON_PASS)
	execute_db_commnads("GRANT ALL PRIVILEGES ON neutron.* TO 'neutron'@'localhost' IDENTIFIED BY '%s';" %NEUTRON_PASS)
	#iuyiuiyui = raw_input('Created SQL Database Neutron')

	#=============
	# Install Neutron
	#=============
	execute("apt-get install neutron-server -y", True)
	execute("apt-get install neutron-plugin-ml2 -y",True)

	add_to_conf(neutron_conf, "database", "connection", "mysql://neutron:%s@localhost/neutron" %NEUTRON_PASS)
	add_to_conf(neutron_conf, "DEFAULT", "auth_strategy", "keystone")

	add_to_conf(neutron_conf, "keystone_authtoken", "auth_uri", "http://%s:5000/v2.0" %ip_address_mgnt)
	add_to_conf(neutron_conf, "keystone_authtoken", "auth_host", ip_address_mgnt)
	add_to_conf(neutron_conf, "keystone_authtoken", "auth_port", "35357")
	add_to_conf(neutron_conf, "keystone_authtoken", "auth_protocol", "http")
	add_to_conf(neutron_conf, "keystone_authtoken", "admin_tenant_name", "service")
	add_to_conf(neutron_conf, "keystone_authtoken", "admin_user", "neutron")
	add_to_conf(neutron_conf, "keystone_authtoken", "admin_password ", NEUTRON_PASS)

	add_to_conf(neutron_conf, "DEFAULT", "rpc_backend", "neutron.openstack.common.rpc.impl_kombu")
	add_to_conf(neutron_conf, "DEFAULT", "rabbit_host", ip_address_mgnt)
	add_to_conf(neutron_conf, "DEFAULT", "rabbit_password", RABBIT_PASS)

	add_to_conf(neutron_conf, "DEFAULT", "nova_region_name", "region")

	add_to_conf(neutron_conf, "DEFAULT", "notify_nova_on_port_status_changes", "True")
	add_to_conf(neutron_conf, "DEFAULT", "notify_nova_on_port_data_changes", "True")
	add_to_conf(neutron_conf, "DEFAULT", "nova_url", "http://%s:8774/v2" %ip_address_mgnt)
	add_to_conf(neutron_conf, "DEFAULT", "nova_admin_username", "nova")
	add_to_conf(neutron_conf, "DEFAULT", "nova_admin_tenant_id", service_tenant)
	add_to_conf(neutron_conf, "DEFAULT", "nova_admin_password", NOVA_PASS)
	add_to_conf(neutron_conf, "DEFAULT", "nova_admin_auth_url", "http://%s:35357/v2.0" %ip_address_mgnt)

	add_to_conf(neutron_conf, "DEFAULT", "core_plugin", "ml2")
	add_to_conf(neutron_conf, "DEFAULT", "service_plugins", "router")
	add_to_conf(neutron_conf, "DEFAULT", "allow_overlapping_ips", "True")

	add_to_conf(neutron_conf, "DEFAULT", "verbose", "True")
	add_to_conf(neutron_conf, "DEFAULT", "debug", "True")
	#add_to_conf(neutron_conf, "DEFAULT", "root_helper", "sudo neutron-rootwrap /etc/neutron/rootwrap.conf")

	#add_to_conf(neutron_paste_conf, "filter:authtoken", "auth_host", ip_address_mgnt)
	#add_to_conf(neutron_paste_conf, "filter:authtoken", "auth_port", "35357")
	#add_to_conf(neutron_paste_conf, "filter:authtoken", "auth_protocol", "http")
	#add_to_conf(neutron_paste_conf, "filter:authtoken", "admin_tenant_name", "service")
	#add_to_conf(neutron_paste_conf, "filter:authtoken", "admin_user", "neutron")
	#add_to_conf(neutron_paste_conf, "filter:authtoken", "admin_password", NEUTRON_PASS)
	
	add_to_conf(neutron_plugin_conf, "ml2", "type_drivers", "gre")
	add_to_conf(neutron_plugin_conf, "ml2", "tenant_network_types", "gre")
	add_to_conf(neutron_plugin_conf, "ml2", "mechanism_drivers", "openvswitch")
	add_to_conf(neutron_plugin_conf, "ml2_type_gre", "tunnel_id_ranges", "1:1000")
	#add_to_conf(neutron_plugin_conf, "ml2_type_vxlan", "vni_ranges", "500:999")
	add_to_conf(neutron_plugin_conf, "securitygroup", "firewall_driver", "neutron.agent.linux.iptables_firewall.OVSHybridIptablesFirewallDriver")
	add_to_conf(neutron_plugin_conf, "securitygroup", "enable_security_group", "True")
	execute("service neutron-server restart", True)
	execute("service nova-api restart", True)
	execute("service nova-scheduler restart", True)
	execute("service nova-conductor restart", True)
	time.sleep(2)
	#iuyiuiyui = raw_input('Installed Neutron')



def install_and_configure_ovs():
	#=============
	# Install OVS
	#=============
	neutron_plugin_conf = "/etc/neutron/plugins/ml2/ml2_conf.ini"
	neutron_dhcp_ini="/etc/neutron/dhcp_agent.ini"
	neutron_l3_ini="/etc/neutron/l3_agent.ini"
	neutron_metadata="/etc/neutron/metadata_agent.ini"

	execute("sed -i 's/#net.ipv4.conf.default.rp_filter=1/net.ipv4.conf.default.rp_filter=0/g' /etc/sysctl.conf",True)
	execute("sed -i 's/#net.ipv4.conf.all.rp_filter=1/net.ipv4.conf.all.rp_filter=0/g' /etc/sysctl.conf",True)

	execute("sysctl -p",True)

	execute("apt-get install openvswitch-switch openvswitch-datapath-dkms -y", True)
	execute("apt-get install neutron-plugin-openvswitch-agent neutron-dhcp-agent neutron-l3-agent neutron-metadata-agent -y", True)

	execute("apt-get install neutron-common neutron-plugin-ml2 -y",True)




	add_to_conf(neutron_plugin_conf, "DATABASE", "sql_connection", "mysql://neutron:%s@localhost/neutron" %NEUTRON_PASS)
	add_to_conf(neutron_plugin_conf, "DATABASE", "connection", "mysql://neutron:%s@localhost/neutron" %NEUTRON_PASS)
	#add_to_conf(neutron_plugin_conf, "OVS", "bridge_mappings", "physnet1:br-%s"%Managment_Interface)
	#add_to_conf(neutron_plugin_conf, "OVS", "network_vlan_ranges", "physnet1:1000:2999")
	#add_to_conf(neutron_plugin_conf, "OVS", "integration_bridge", "br-int")
	add_to_conf(neutron_plugin_conf, "OVS", "local_ip", ip_address_tunneling)
	add_to_conf(neutron_plugin_conf, "OVS", "tunnel_types", "gre")
	add_to_conf(neutron_plugin_conf, "OVS", "enable_tunneling", "True")


	add_to_conf(neutron_dhcp_ini, "DEFAULT", "interface_driver", "neutron.agent.linux.interface.OVSInterfaceDriver")
	add_to_conf(neutron_dhcp_ini, "DEFAULT", "dhcp_driver", "neutron.agent.linux.dhcp.Dnsmasq")
	add_to_conf(neutron_dhcp_ini, "DEFAULT", "use_namespaces", "True")

	add_to_conf(neutron_l3_ini, "DEFAULT", "interface_driver", "neutron.agent.linux.interface.OVSInterfaceDriver")
	add_to_conf(neutron_l3_ini, "DEFAULT", "use_namespaces", "True")


	add_to_conf(neutron_metadata, "DEFAULT", "auth_url", "http://%s:5000/v2.0" %ip_address_mgnt)
	add_to_conf(neutron_metadata, "DEFAULT", "auth_region", "region")
	add_to_conf(neutron_metadata, "DEFAULT", "admin_tenant_name", "service")
	add_to_conf(neutron_metadata, "DEFAULT", "admin_user", "neutron")
	add_to_conf(neutron_metadata, "DEFAULT", "admin_password", NEUTRON_PASS)
	add_to_conf(neutron_metadata, "DEFAULT", "nova_metadata_ip", ip_address_mgnt)
	add_to_conf(neutron_metadata, "DEFAULT", "metadata_proxy_shared_secret", ADMINTOKEN)
	add_to_conf(neutron_metadata, "DEFAULT", "verbose", "True")


	execute("service openvswitch-switch restart",True)
	time.sleep(2)

	#iuyiuiyui = raw_input('Installed OVS... before the bridges')


	full_cidr = str(netaddr.IPNetwork(ip_address + "/" + ip_mask).cidr)


	execute("ovs-vsctl --may-exist add-br br-int")
	execute("ovs-vsctl --may-exist add-br br-ex")
	execute("ovs-vsctl --may-exist add-port br-ex %s"%Web_Interface)

	#execute("ifconfig eth0 0.0.0.0",True)
	#execute("ifconfig br-ex %s"%ip_address_mgnt,True)
	#execute("dhclient",True)

	execute("ethtool -K %s gro off"%Web_Interface,True)

	execute("service nova-api restart", True)
	execute("service neutron-plugin-openvswitch-agent restart", True)
	execute("service neutron-dhcp-agent restart", True)
	execute("service neutron-l3-agent restart", True)
	execute("service neutron-metadata-agent restart", True)
	time.sleep(2)
	#iuyiuiyui = raw_input('Installed OVS and bridges')





def install_and_configure_dashboard():
	execute("apt-get install apache2 memcached libapache2-mod-wsgi openstack-dashboard -y", True)
	execute("apt-get remove --purge openstack-dashboard-ubuntu-theme -y", True);

	execute("service apache2 restart", True)
	execute("service memcached restart", True)
	time.sleep(2)

def add_cirros_image():

	execute("mkdir /tmp/images",True)
	execute("cd /tmp/images/",True)
	execute("wget http://cdn.download.cirros-cloud.net/0.3.2/cirros-0.3.2-x86_64-disk.img",True)
	execute("glance --os-username admin --os-password %s --os-tenant-name admin --os-auth-url http://%s:5000/v2.0 image-create --name \"cirros-0.3.2-x86_64\" --disk-format qcow2 --container-format bare --is-public True --progress < cirros-0.3.2-x86_64-disk.img" %(ADMIN_TENANT_PASS,ip_address_mgnt),True)

def create_initial_network():
	
	ip_parts = ip_address.split(".",4)

	ext_start_address = ip_parts[0] + "." + ip_parts[1] + "." + ip_parts[2] + "." + "200"
	ext_end_address = ip_parts[0] + "." + ip_parts[1] + "." + ip_parts[2] + "." + "253"

	full_cidr = str(netaddr.IPNetwork(ip_address + "/" + ip_mask).cidr)

	execute("neutron --os-username admin --os-password %s --os-tenant-name admin --os-auth-url http://%s:5000/v2.0 net-create ext-net --shared --router:external=True"%(ADMIN_TENANT_PASS,ip_address_mgnt),True)
	execute("neutron --os-username admin --os-password %s --os-tenant-name admin --os-auth-url http://%s:5000/v2.0 subnet-create ext-net --name ext-subnet --allocation-pool start=%s,end=%s --disable-dhcp --gateway %s %s"%(ADMIN_TENANT_PASS,ip_address_mgnt,ext_start_address,ext_end_address,ip_address_gateway,full_cidr),True)

def install_and_configure_nova_compute():
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

	#add_to_conf(nova_paste_conf, "filter:authtoken", "auth_host", ip_address_mgnt)
	#add_to_conf(nova_paste_conf, "filter:authtoken", "auth_port", "35357")
	#add_to_conf(nova_paste_conf, "filter:authtoken", "auth_protocol", "http")
	#add_to_conf(nova_paste_conf, "filter:authtoken", "admin_tenant_name", "service")
	#add_to_conf(nova_paste_conf, "filter:authtoken", "admin_user", "nova")
	#add_to_conf(nova_paste_conf, "filter:authtoken", "admin_password", NOVA_PASS)

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
	#add_to_conf(nova_conf, "DEFAULT", "libvirt_vif_driver", "nova.virt.libvirt.vif.LibvirtGenericVIFDriver")
	#add_to_conf(nova_conf, "DEFAULT", "root_helper", "sudo nova-rootwrap /etc/nova/rootwrap.conf")

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
	#add_to_conf(nova_compute_conf, "DEFAULT", "compute_driver", "libvirt.LibvirtDriver")
	#add_to_conf(nova_compute_conf, "DEFAULT", "libvirt_vif_type", "ethernet")
  
	execute("service libvirt-bin restart", True)
	execute("service nova-compute restart", True)
	time.sleep(2)


def install_and_configure_ovs_compute():
	neutron_conf = "/etc/neutron/neutron.conf"
	neutron_paste_conf = "/etc/neutron/api-paste.ini"
	neutron_plugin_conf = "/etc/neutron/plugins/ml2/ml2_conf.ini" 

	execute("sed -i 's/#net.ipv4.conf.default.rp_filter=1/net.ipv4.conf.default.rp_filter=0/g' /etc/sysctl.conf",True)
	execute("sed -i 's/#net.ipv4.conf.all.rp_filter=1/net.ipv4.conf.all.rp_filter=0/g' /etc/sysctl.conf",True)

	execute("sysctl -p",True)

	#execute("apt-get install neutron-common neutron-plugin-ml2 openvswitch-switch openvswitch-datapath-dkms -y", True)
	
	execute("apt-get install neutron-common neutron-plugin-ml2 -y",True)

  
	#execute("apt-get install neutron-plugin-openvswitch-agent -y", True)

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
	#add_to_conf(neutron_conf, "DEFAULT", "root_helper", "sudo neutron-rootwrap /etc/neutron/rootwrap.conf")

	#add_to_conf(neutron_conf, "database", "connection", "mysql://neutron:%s@%s/neutron" %(NEUTRON_PASS,ip_address_mgnt))

	#add_to_conf(neutron_paste_conf, "filter:authtoken", "auth_host", ip_address_mgnt)
	#add_to_conf(neutron_paste_conf, "filter:authtoken", "auth_port", "35357")
	#add_to_conf(neutron_paste_conf, "filter:authtoken", "auth_protocol", "http")
	#add_to_conf(neutron_paste_conf, "filter:authtoken", "admin_tenant_name", "service")
	#add_to_conf(neutron_paste_conf, "filter:authtoken", "admin_user", "neutron")
	#add_to_conf(neutron_paste_conf, "filter:authtoken", "admin_password", NEUTRON_PASS)
	

	add_to_conf(neutron_plugin_conf, "ml2", "type_drivers", "gre")
	add_to_conf(neutron_plugin_conf, "ml2", "tenant_network_types", "gre")
	add_to_conf(neutron_plugin_conf, "ml2", "mechanism_drivers", "openvswitch")

	#add_to_conf(neutron_plugin_conf, "ml2_type_vlan", "network_vlan_ranges", "physnet1:2000:2999")
	#add_to_conf(neutron_plugin_conf, "ml2_type_vxlan", "vni_ranges", "500:999")
	add_to_conf(neutron_plugin_conf, "ml2_type_gre", "tunnel_id_ranges", "1:1000")

	add_to_conf(neutron_plugin_conf, "securitygroup", "firewall_driver", "neutron.agent.linux.iptables_firewall.OVSHybridIptablesFirewallDriver")
	add_to_conf(neutron_plugin_conf, "securitygroup", "enable_security_group", "True")
	#add_to_conf(neutron_plugin_conf, "DATABASE", "sql_connection", "mysql://neutron:%s@%s/neutron" %(NEUTRON_PASS,ip_address_mgnt))
	#add_to_conf(neutron_plugin_conf, "DATABASE", "connection", "mysql://neutron:%s@%s/neutron" %(NEUTRON_PASS,ip_address_mgnt))
	
	#add_to_conf(neutron_plugin_conf, "OVS", "bridge_mappings", "physnet1:br-eth0")
	#add_to_conf(neutron_plugin_conf, "OVS", "tenant_network_type", "gre")
	add_to_conf(neutron_plugin_conf, "OVS", "tunnel_types", "gre")
	add_to_conf(neutron_plugin_conf, "OVS", "enable_tunneling", "True")
	#add_to_conf(neutron_plugin_conf, "OVS", "network_vlan_ranges", "physnet1:1000:2999")
	#add_to_conf(neutron_plugin_conf, "OVS", "integration_bridge", "br-int")
	add_to_conf(neutron_plugin_conf, "OVS", "local_ip", tunnel_ip)

	execute("service neutron-plugin-openvswitch-agent restart", True)
	execute("service openvswitch-switch restart", True)
	time.sleep(2)
	execute("ovs-vsctl --may-exist add-br br-int",True)

initialize_system()
install_and_configure_ntp()
install_rabbitmq()
install_database()
install_and_configure_keystone()
create_keystone_users()
install_command_line()
install_and_configure_glance()
install_and_configure_nova()
install_and_configure_neutron()
install_and_configure_ovs()
install_and_configure_dashboard()
add_cirros_image()
create_initial_network()
install_and_configure_nova_compute()
install_and_configure_ovs_compute()

print_format(" Installation successfull! Login into horizon http://%s/horizon  Username:admin  Password:%s " % (ip_address,ADMIN_TENANT_PASS))
