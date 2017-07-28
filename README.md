## AWS EC2 Access Check

This script provides the answer to one specific question:

Given an AWS EC2 instance name and IP (address or subnet), is traffic
allowed in any of the security groups associated with that instance?

Print the security group name, subnet and type of traffic allowed for
each IP match.

Helps in auditing existing security policies, and determining the correct
security group when adding new policies.

### Positional arguments

* `instance-id` - Instance ID as it appears in AWS
* `ip` - Either single IP or subnet in CIDR format
* `direction` - Must be set to 'ingress' or 'egress'

### Optional arguments

* `-ignore` - Must be set to '1' to ignore 0.0.0.0/0 entries 

### AWS credentials

For configuring your AWS connection, see boto3 instructions:

http://boto3.readthedocs.io/en/latest/guide/configuration.html

One way is to configure a shared credential file and AWS config file. 
It is recommended to configure a separate API user in AWS IAM for
this purpose, with its own access id and access key.

### Installation

The script relies on some additional Python modules: boto3 and netaddr
(which can both be installed with pip).

### Examples

See all inbound rules for instance i-01234aaaaaaaaaaaa, IP 8.8.8.8

`aws_access_check.py i-01234aaaaaaaaaaaa 8.8.8.8 ingress`

See all outbound rules for instance i-01234aaaaaaaaaaaa, subnet 8.8.8.0/24

`aws_access_check.py i-01234aaaaaaaaaaaa 8.8.8.0/24 egress`

See all inbound rules for instance i-01234aaaaaaaaaaaa, IP 8.8.8.8, ignore 0.0.0.0/0 prefix

`aws_access_check.py i-01234aaaaaaaaaaaa 8.8.8.8 ingress -ignore 1`

