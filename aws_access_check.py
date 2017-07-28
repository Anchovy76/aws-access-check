#!/usr/bin/env python

'''
Copyright 2017 Jan Ruohonen

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

This script provides the answer to one specific question:

Given an AWS EC2 instance name and IP (address or subnet), is traffic
allowed in any of the security groups associated with that instance?

Print the security group name, subnet and type of traffic allowed for
each IP match. 

Helps in auditing existing security policies, and determining the correct
security group when adding new policies.
'''

import boto3,argparse,sys,netaddr

# Functions to validate IP/subnet given as command line argument

def ip_validation(candidate_ip):
    try:
        addr_input = netaddr.IPAddress(candidate_ip)
        return True
    except:
        return False

def subnet_validation(candidate_subnet):
    try:
        addr_input = netaddr.IPNetwork(candidate_subnet)
        return True
    except:
        return False

# Verify that all necessary command line arguments have been given

parser = argparse.ArgumentParser(description='Match particular IP to AWS EC2 SG rules - IPv4 supported')
parser.add_argument('instance_id', help='Instance ID as it appears in AWS')
parser.add_argument('ip', help='IP address or subnet')
parser.add_argument('direction', help='ingress or egress')
parser.add_argument('-ignore', type=int, help='Set to 1 to ignore default route CIDR entries') 
args = parser.parse_args()

if ip_validation(args.ip):
    src_ip = netaddr.IPAddress(args.ip)
elif subnet_validation(args.ip):
    src_ip = netaddr.IPNetwork(args.ip)
else:
    print "There is a problem with the IP address argument"
    sys.exit()

if args.direction == "ingress":
    direction = "IpPermissions"
elif args.direction == "egress":
    direction = "IpPermissionsEgress"
else:
    print "There is a problem with the direction argument - has to be ingress or egress"
    sys.exit()

client = boto3.client('ec2')

# Collect a list of all security groups associated with an instance (instance name from args.instance_id)

security_group_list = []

try:
    instance_response = client.describe_instances(InstanceIds=[args.instance_id])
except:
    print sys.exc_info()[1]
    sys.exit()

# We should get exactly one instance in the response, therefore we use an index of zero for both Reservations and Instances
# All instances must have at least one security group attached

for group_specification in instance_response['Reservations'][0]['Instances'][0]['SecurityGroups']:
    security_group_list.append(group_specification['GroupName'])

# Retrieve specifics for all listed security groups in one query

try:
    security_response = client.describe_security_groups(Filters=[ { 'Name': 'group-name', 'Values': security_group_list } ] )
except:
    print sys.exc_info()[1]
    sys.exit()

# For each security group, find IpPermissions/IpPermissionsEgress items

for group_item in security_response['SecurityGroups']:
    for ip_permissions_item in group_item[direction]:

# Find out if FromPort and ToPort are defined in the permissions entry

        if ip_permissions_item.has_key('FromPort') and ip_permissions_item.has_key('ToPort'):
            start_port = ip_permissions_item['FromPort']
            end_port = ip_permissions_item['ToPort']
        else:
            start_port = "none defined"
            end_port = "none defined"

        protocol_info = ip_permissions_item['IpProtocol']

# Here we define special interpretations per protocol

        if protocol_info == "-1":
            protocol_info = "all"

        if protocol_info == "icmp":
            icmp_code = str(ip_permissions_item['FromPort'])
	    if icmp_code == "-1":
                icmp_code = "all"
            start_port = "none defined"
            end_port = "icmp code " + icmp_code

# Finally check if one of the IP prefixes contains the IP/subnet given in script args

        for cidr_item in ip_permissions_item['IpRanges']:
            for cidr_key, cidr_value in cidr_item.items():
                if cidr_value == "0.0.0.0/0" and args.ignore == 1:
                    break
                candidate_subnet = netaddr.IPNetwork(cidr_value)
                if src_ip in candidate_subnet:
                    print "Match found in group", group_item['GroupName'], "subnet", candidate_subnet
                    print "Protocol " + protocol_info + " start/end port " + str(start_port) + "/" + str(end_port) + "\n"
