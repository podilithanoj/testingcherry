#!/usr/bin/env python

import re
import sys
import json
import time
import boto3
from boto3.session import Session
import ConfigParser
from jinja2 import Environment, FileSystemLoader
from botocore.exceptions import ClientError


def usage():
    """ Script Usage """
    print("Usage: ./launch_elb.py cluster_id prod/dev")
    print("Example: ./launch_elb.py oa-staging dev")
    exit(5)


def define_sg_permissions(env, con, acces_map, sec_group_id, entity):
    lookup_key = entity + "_portmap"
    sec_group_perms = []

    

    for src in entry_map["source"].values():
        for port in entry_map["port"].values():
            sec_group_perms.append(get_ip_permissions_json("tcp", int(port), int(port), src))

    if entity == 'cluster':
        sec_group_perms.append(
                {'IpProtoco': '-1',
                 'FromPort': 0,
                 'ToPort': 65535,
                 'UserIdGroupPairs': [{'GroupId': sec_group_id}]}
        )

    conn.authorize_security_group_ingress(
        GroupId=sec_group_id,
        IpPermissions=sec_group_perms
    )



def get_ip_permissions_json(protocol, from_port, to_port, cidr_ip):
    return {'IpProtocol': protocol, 'FromPort': from_port, 'ToPort': to_port, 'IpRanges': [{'CidrIp': cidr_ip}]}



def create_cluster_private_elb_sg(conn, cluster_sg_id, vpc, cluster_id):
    sec_group = conn.create_security_group(GroupName='blitz-' + cluster_id + '-private-elb',
                                           Description='Security group for private ELBs of cluster ' + cluster_id,
                                           VpcId=vpc)
    conn.authorize_security_group_ingress(
        GroupId=sec_group['GroupId'],
        IpPermissions=[
            {'IpProtocol': 'tcp',
             'FromPort': 443,
             'ToPort': 443,
             'UserIdGroupPairs': [{'GroupId': cluster_sg_id}]},
        ])

    return sec_group['GroupId']



def update_cluster_security_group(ec2, port, src_group_id, cluster_id):
    try:
        cluster_sg_list = filter(lambda sg: 'blitz-' + cluster_id == sg['GroupName'],
                                 ec2.describe_security_groups()['SecurityGroups'])
        if len(cluster_sg_list) == 1:
            cluster_sg = max(cluster_sg_list)
            ec2.authorize_security_group_ingress(
                GroupId=cluster_sg['GroupId'],
                IpPermissions=[
                    {'IpProtocol': 'tcp',
                     'FromPort': port,
                     'ToPort': port,
                     'UserIdGroupPairs': [{'GroupId': src_group_id}]}
                ])
            return True
        else:
            raise Exception("Cluster security group not present. Please review")
    except ClientError:
        # Cluster security group already authorized
        return False


def create_lbs(elb_conn, cluster_id, public_subnets, private_subnets, public_hosted_zone_name, private_hosted_zone_name, cross_acc_route53_role_arn, private_elb):
    """ Create the load balancers """
    global collector, reader, querytool
    roles = [collector, reader, querytool]
    elb_hosted_zone_id = None
    changed = False
    route53_client = None

    if cross_acc_route53_role_arn:
        sts_client = boto3.client('sts')
        response = sts_client.assume_role(RoleArn=cross_acc_route53_role_arn, RoleSessionName="cross-acc-session")

        if 'Credentials' not in response:
            raise Exception("Error while trying to assume role : %s" % cross_acc_route53_role_arn)

        session = Session(aws_access_key_id=response['Credentials']['AccessKeyId'],
                        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                        aws_session_token=response['Credentials']['SessionToken'])

        route53_client = session.client('route53')
    else:
        route53_client = boto3.client('route53')
    
    if private_elb:
        roles.extend([collectorPrivate, readerPrivate])

    for role in roles:
        elb_name = 'blitz-' + cluster_id + "-" + role['name']

        try:
            elb_list = elb_conn.describe_load_balancers(LoadBalancerNames=[
                elb_name,
            ])['LoadBalancerDescriptions']
        except:
            elb_list = []

        if len(elb_list) == 0:
            elb_name = 'blitz-' + cluster_id + "-" + role['name']

            if re.match('^.*-pri$', elb_name) is not None or public_subnets is None:
                subnets = private_subnets
            else:
                subnets = public_subnets

            elb = elb_conn.create_load_balancer(
                LoadBalancerName=elb_name,
                Listeners=[
                    role['ports']
                ],
                AvailabilityZones=[],
                Subnets=subnets,
                SecurityGroups=[
                    role['sg'],
                ],
                Scheme=role['scheme']
            )

            elb_conn.configure_health_check(
                LoadBalancerName=elb_name,
                HealthCheck={
                    'Target': role['health_check'],
                    'Interval': 15,
                    'Timeout': role['timeout'],
                    'UnhealthyThreshold': 2,
                    'HealthyThreshold': 2
                }
            )

            idle_timeout = 5
            if role['name'] == "reader" or role['name'] == "reader-pri" or role['name'] == "querytool":
                idle_timeout = 300
            elif role['name'] == "collector" or role['name'] == "collector-pri":
                idle_timeout = 60

            elb_conn.modify_load_balancer_attributes(
                LoadBalancerName=elb_name,
                LoadBalancerAttributes={
                    'ConnectionDraining': {
                        'Enabled': True,
                        'Timeout': 20
                    },
                    'ConnectionSettings': {
                        'IdleTimeout': idle_timeout
                    }
                }
            )

            reference_policy = "ELBSecurityPolicy-TLS-1-1-2017-01"
            cipher_policy = "custom-" + reference_policy

            elb_conn.create_load_balancer_policy(
                LoadBalancerName=elb_name,
                PolicyName=cipher_policy,
                PolicyTypeName='SSLNegotiationPolicyType',
                PolicyAttributes=[
                    {
                        'AttributeName': 'Reference-Security-Policy',
                        'AttributeValue': reference_policy
                    }
                ]
            )

            elb_conn.set_load_balancer_policies_of_listener(
                LoadBalancerName=elb_name,
                LoadBalancerPort=role['ports']['LoadBalancerPort'],
                PolicyNames=[
                    cipher_policy
                ]
            )
            elb_client.add_tags(
                LoadBalancerNames=elb_name,
                Tags=[
                {
                'Key' : "ResourceOwner",
                'Value' : "Bhanu Kovuri"
                },
                {
                'Key' : "JIRAProject",
                'Value': "Blitz"
                },
                {
                'Key' : "IntendedPublic",
                'Value' : "False"
                },
                {
                'Key' : "DeploymentEnvironment",
                'Value' : env
                },
                {
                'Key' : "CostCenter",
                'Value': "Blitz-"+env
                }
                ]
                )


            if not elb_hosted_zone_id:
                elb_client = boto3.client('elb')
                response = elb_client.describe_load_balancers(LoadBalancerNames = [elb_name])
                elb_hosted_zone_id = response['LoadBalancerDescriptions'][0]['CanonicalHostedZoneNameID']

            # Register instances present in current public ELB to private ELB
            if role['name'] == collectorPrivate['name']:
                register_private_elb_instances(elb_conn, collector, elb_name)
            if role['name'] == readerPrivate['name']:
                register_private_elb_instances(elb_conn, reader, elb_name)


            if re.match('^.*-pri$', elb_name) is not None or public_subnets is None:
                hosted_zone_name = private_hosted_zone_name
            else:
                hosted_zone_name = public_hosted_zone_name

            if not hosted_zone_name:
                raise Exception("Hosted Zone undefined!!! Exiting...")

            # Check for an existing A record on Route53. If it exists, delete it. Then, create a new A record
            exists, hosted_zone_id, record_name, dns_name = check_for_a_record(elb_name + '.' + hosted_zone_name, hosted_zone_name, route53_client)

            if exists:
                # Delete old record which is pointing to a non existing ELB
                delete_a_record(hosted_zone_id, record_name, dns_name, elb_hosted_zone_id, route53_client)

            # Create A record pointing to the newly created ELB
            create_a_record(elb_name + '.' + hosted_zone_name, elb['DNSName'], hosted_zone_name, elb_hosted_zone_id, route53_client)

            changed = True

    return changed



def register_private_elb_instances(elb_conn, component, private_elb_name):
        elb_name = 'blitz-' + cluster_id + "-" + component['name']
        try:
            elb_list = elb_conn.describe_load_balancers(LoadBalancerNames=[
                elb_name,
            ])['LoadBalancerDescriptions']
        except:
            elb_list = []

        # register all instances currently behind the internet facing collector ELB to private ELB
        if len(elb_list) == 1:
            instance_list = elb_conn.describe_instance_health(LoadBalancerName=elb_name)['InstanceStates']
            instance_ids = [{'InstanceId': instance['InstanceId']} for instance in instance_list]
            if (len(instance_ids)) > 0:
                elb_conn.register_instances_with_load_balancer(
                    LoadBalancerName=private_elb_name,
                    Instances=instance_ids
                )
        return True


# Creates security groups for collector, reader and querytool components. Calls cluster level security group creation
# Passes along the security group created for the component so that cluster level security group can add an inbound rule
def create_security_groups(env, cluster_id, conn, vpc, access_map):
    global collector, reader, querytool
    changed = False

    components = [collector, reader, querytool]

    for component in components:
        all_sg = conn.describe_security_groups()
        sg_list = filter(lambda sg: 'blitz-' + cluster_id + '-' + component['name'] + '-elb' == sg['GroupName'],
                         all_sg['SecurityGroups'])
        if len(sg_list) == 0:
            group = conn.create_security_group(
                GroupName='blitz-' + cluster_id + '-' + component['name'] + '-elb',
                Description='Security group for ' + cluster_id + ' ' + component['name'] + ' ELB', VpcId=vpc)

            component['sg'] = group['GroupId']
            define_sg_permissions(env, conn, access_map, component['sg'], 'elb')
            create_update_cluster_security_group(env, conn, access_map, cluster_id, component, group, vpc)
            changed = True

    return changed


# Create cluster level security group if it doesn't exist. Add an inbound rule for the component security group
def create_update_cluster_security_group(env, conn, access_map, cluster_id, component, group, vpc):
    # check for existence of main cluster security group
    # If it doesn't exist, create from scratch, if exists, update with port
    all_sg = conn.describe_security_groups()
    sg_list = filter(lambda sg: 'blitz-' + cluster_id == sg['GroupName'], all_sg['SecurityGroups'])
    if len(sg_list) == 1:
        # exists, only update with new group
        cluster_sg = max(sg_list)

        # authorize ports for security group.
        conn.authorize_security_group_ingress(
            GroupId=cluster_sg['GroupId'],
            IpPermissions=[
                {'IpProtocol': 'tcp',
                 'FromPort': component['ports']['InstancePort'],
                 'ToPort': component['ports']['InstancePort'],
                 'UserIdGroupPairs': [{'GroupId': group['GroupId']}]}
            ])
        return cluster_sg['GroupId']
    elif len(sg_list) == 0:
        sec_group = conn.create_security_group(
            GroupName='blitz-' + cluster_id,
            Description='Security group for ' + cluster_id, VpcId=vpc)

        conn.create_tags(
            DryRun=False,
            Resources=[
                sec_group['GroupId'],
            ],
            Tags=[
                {
                    'Key': 'cluster',
                    'Value': cluster_id
                },
            ]
        )

        conn.authorize_security_group_ingress(
            GroupId=sec_group['GroupId'],
            IpPermissions=[
                {'IpProtocol': 'tcp',
                 'FromPort': component['ports']['InstancePort'],
                 'ToPort': component['ports']['InstancePort'],
                 'UserIdGroupPairs': [{'GroupId': group['GroupId']}]}
            ])

        define_sg_permissions(env, conn, access_map, sec_group['GroupId'], 'cluster')
        return sec_group['GroupId']


def main(env, cluster_id, vpc, public_subnets, private_subnets, public_hosted_zone_name, private_hosted_zone_name, cross_acc_route53_role_arn, access_map, private_elb=None):
    """ main function """
    ec2 = boto3.client("ec2")
    elb_conn = boto3.client('elb')
    changed = False
    failed = False
    message = ""

    try:
        # Create security groups for all components
        changed = create_security_groups(env, cluster_id, ec2, vpc, access_map)

        if private_elb:
            # Check for blitz-<cluster-id>-private-elb security group and create if it doesn't exist
            all_sg = ec2.describe_security_groups()
            cluster_sg_id = max(filter(lambda sg: 'blitz-' + cluster_id == sg['GroupName'], all_sg['SecurityGroups']))[
                'GroupId']

            cluster_private_elb_sg_list = filter(lambda sg: 'blitz-' + cluster_id + '-private-elb' == sg['GroupName'],
                                                 all_sg['SecurityGroups'])
            if len(cluster_private_elb_sg_list) == 1:
                cluster_private_elb_sg_id = max(cluster_private_elb_sg_list)['GroupId']
            else:
                cluster_private_elb_sg_id = create_cluster_private_elb_sg(ec2, cluster_sg_id, vpc, cluster_id)
                changed = changed | True

            # Set the security group values for private ELBs
            collectorPrivate['sg'] = cluster_private_elb_sg_id
            readerPrivate['sg'] = cluster_private_elb_sg_id
            changed = changed | update_cluster_security_group(ec2, 40000, cluster_private_elb_sg_id, cluster_id)
            changed = changed | update_cluster_security_group(ec2, 30000, cluster_private_elb_sg_id, cluster_id)

        # Create ELBs
        changed = changed | create_lbs(elb_conn, cluster_id, public_subnets, private_subnets, public_hosted_zone_name, private_hosted_zone_name, cross_acc_route53_role_arn, private_elb)

        time.sleep(10)
    except Exception as e:
        message = str(e)
        failed = True

    print(json.dumps)({
        "changed": changed,
        "failed": failed,
        "message": message
    })


def check_for_a_record(elb_name, hosted_zone_name, route53_client):
    if not route53_client:
        route53_client = boto3.client('route53')

    response = route53_client.list_hosted_zones_by_name()
    for zone in response['HostedZones']:
        if zone['Name'] == hosted_zone_name:
            resource_records = route53_client.list_resource_record_sets(HostedZoneId=zone['Id'],StartRecordName=elb_name)['ResourceRecordSets']
            for resourceRecord in resource_records:
                if 'AliasTarget' in resourceRecord and resourceRecord['Type'] == 'A':
                    if elb_name.lower() in resourceRecord['Name']:
                        return True, zone['Id'], resourceRecord['Name'], resourceRecord['AliasTarget']['DNSName']
    return False, None, None, None



# Z1H1FL5HABSF5 is the HostedZoneId for us-west-2 - https://docs.aws.amazon.com/general/latest/gr/rande.html#elb_region
def create_a_record(record_name, dns_name, hosted_zone_name, elb_hosted_zone_id, route53_client):
    if not route53_client:
        route53_client = boto3.client('route53')

    response = route53_client.list_hosted_zones_by_name()
    hosted_zone_id = None
    for zone in response['HostedZones']:
        if zone['Name'] == hosted_zone_name:
            hosted_zone_id = zone['Id']
    if hosted_zone_id is None:
        return False
    try:
        route53_client.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch={
                'Comment': 'CREATE A record',
                'Changes': [
                    {
                        'Action': 'CREATE',
                        'ResourceRecordSet': {
                            'Name': record_name,
                            'Type': 'A',
                            'AliasTarget': {
                                'HostedZoneId': elb_hosted_zone_id,
                                'EvaluateTargetHealth': False,
                                'DNSName': dns_name
                            }
                        }
                    }
                ]
            })
    except Exception as e:
        raise e


def delete_a_record(hosted_zone_id, record_name, dns_name, elb_hosted_zone_id, route53_client):
    if not route53_client:
        route53_client = boto3.client('route53')

    try:
        route53_client.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch={
                'Comment': 'DELETE A record',
                'Changes': [
                    {
                        'Action': 'DELETE',
                        'ResourceRecordSet': {
                            'Name': record_name,
                            'Type': 'A',
                            'AliasTarget': {
                                'HostedZoneId': elb_hosted_zone_id,
                                'EvaluateTargetHealth': False,
                                'DNSName': dns_name
                            }
                        }
                    }
                ]
            })
    except Exception as e:
        raise e


def get_generic_parameters(env):
    config = ConfigParser.SafeConfigParser(allow_no_value=True)
    env_ini_path = 'inventory/aws-env.ini'
    config.read(env_ini_path)

    vpc = config.get(env, 'vpc')
    region = config.get(env, 'region')
    account = config.get(env, 'account')
    public_subnets = config.get(env, 'public_subnets')
    if public_subnets:
        public_subnets = public_subnets.split(',')
    private_subnets = config.get(env, 'private_subnets').split(',')
    elb_scheme = config.get(env, 'elb_scheme')
    ssl_cert_name = config.get(env, 'ssl_cert')
    private_elb_ssl_cert_name = config.get(env, 'private_elb_ssl_cert')
    public_hosted_zone_name = config.get(env, 'public_hosted_zone_name')
    private_hosted_zone_name = config.get(env, 'private_hosted_zone_name')
    cross_acc_route53_role_arn = config.get(env, 'cross_acc_route53_role_arn')

    #construct ARN for the certificate
    ssl_cert = "arn:aws:acm:" + region + ":" + account + ":certificate/" + ssl_cert_name

    private_elb_ssl_cert = None

    if private_elb_ssl_cert_name:
        private_elb_ssl_cert = "arn:aws:acm:" + region + ":" + account + ":certificate/" + private_elb_ssl_cert_name

    return (ssl_cert, private_elb_ssl_cert, public_hosted_zone_name, private_hosted_zone_name, cross_acc_route53_role_arn, vpc, public_subnets, private_subnets, region, elb_scheme)



def get_source_port_map(env):
    env_vars = dict()
    env_file = "inventory/env_layout/layout-env-" + env + ".json"

    with open(env_file, "r") as access_file:
        env_vars = json.load(access_file)

    elb_access_map = dict()
    cluster_access_map = dict()

    for src in env_vars["elb_inbound_source"]:
        elb_access_map[src] = env_vars["source_cidr_map"][src]

    for src in env_vars["cluster_inbound_source"]:
        cluster_access_map[src] = env_vars["source_cidr_map"][src]

    j2_env = Environment(loader=FileSystemLoader('inventory/templates'))
    
    mapping_template = j2_env.get_template('source_port_mapping.json.j2')
    source_port_map = mapping_template.render(elb_access_map=elb_access_map, cluster_access_map=cluster_access_map)

    return json.loads(source_port_map)



if __name__ == '__main__':
    try:
        cluster_id = sys.argv[1]
        env = sys.argv[2]
    except:
        usage()

    ssl_cert, private_elb_ssl_cert, public_hosted_zone_name, private_hosted_zone_name, cross_acc_route53_role_arn, vpc, public_subnets, private_subnets, region, elb_scheme = get_generic_parameters(env)

    access_map = get_source_port_map(env)

    collector = {
        'name': 'collector',
        'ports': {
            'Protocol': 'HTTPS',
            'LoadBalancerPort': 443,
            'InstanceProtocol': 'HTTP',
            'InstancePort': 40000,
            'SSLCertificateId': ssl_cert
        },
        'health_check': 'HTTP:40000/ping',
        'timeout': 5,
        'sg': '',
        'scheme': elb_scheme
    }

    reader = {
        'name': 'reader',
        'ports': {
            'Protocol': 'HTTPS',
            'LoadBalancerPort': 443,
            'InstanceProtocol': 'HTTP',
            'InstancePort': 30000,
            'SSLCertificateId': ssl_cert
        },
        'health_check': 'HTTP:30000/ping',
        'timeout': 5,
        'sg': '',
        'scheme': elb_scheme
    }

    collectorPrivate = {
        'name': 'collector-pri',
        'ports': {
            'Protocol': 'HTTPS',
            'LoadBalancerPort': 443,
            'InstanceProtocol': 'HTTP',
            'InstancePort': 40000,
            'SSLCertificateId': private_elb_ssl_cert
        },
        'health_check': 'HTTP:40000/ping',
        'timeout': 5,
        'sg': '',
        'scheme': 'internal'
    }

    readerPrivate = {
        'name': 'reader-pri',
        'ports': {
            'Protocol': 'HTTPS',
            'LoadBalancerPort': 443,
            'InstanceProtocol': 'HTTP',
            'InstancePort': 30000,
            'SSLCertificateId': private_elb_ssl_cert
        },
        'health_check': 'HTTP:30000/ping',
        'timeout': 5,
        'sg': '',
        'scheme': 'internal'
    }

    querytool = {
        'name': 'querytool',
        'ports': {
            'Protocol': 'HTTPS',
            'LoadBalancerPort': 443,
            'InstanceProtocol': 'HTTP',
            'InstancePort': 20000,
            'SSLCertificateId': ssl_cert
        },
        'health_check': 'HTTP:20000/ping',
        'timeout': 5,
        'sg': '',
        'scheme': elb_scheme
    }

    main(env, cluster_id, vpc, public_subnets, private_subnets, public_hosted_zone_name, private_hosted_zone_name, cross_acc_route53_role_arn, access_map, private_elb_ssl_cert)