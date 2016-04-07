#!/usr/bin/env python

import os
import re
import sys
import urllib2
import ConfigParser
import click
import boto.ec2


@click.command()
@click.argument('ports', nargs=-1)
@click.option('-c', '--config', default="sesamum.conf", help='Config file')
@click.option('-d', '--dry-run', default=False, type=bool, help='Perform all operations in dry run')
@click.option('-r', '--region', default='us-west-2', help='The AWS region to target')
@click.option('-p', '--profile', default='staging', help='The boto credentials profile to use')
@click.option('-l', '--list-groups', is_flag=True, help='List all security groups for a given region / profile')
def main(ports, config, dry_run, region, profile, list_groups):

    print ANSI.PURP + " ___  ___ ___  __ _ _ __ ___  _   _ _ __ ___"
    print "/ __|/ _ / __|/ _` | '_ ` _ \| | | | '_ ` _ \\"
    print "\__ |  __\__ | (_| | | | | | | |_| | | | | | |"
    print "|___/\___|___/\__,_|_| |_| |_|\__,_|_| |_| |_|\n" + ANSI.ENDC

    configuration = get_configuration(config)
    conn = get_ec2_connection(region, profile)

    if list_groups:
        list_security_groups(conn)
        sys.exit(0)

    groups = parse_groups(ports)

    if len(groups) < 1:
        print ANSI.RED + "Please specify one or more security groups + ports to operate on." + ANSI.ENDC
        print ANSI.RED + "eg: `sesamum -r us-east-1 -p production foo:22,443 bar:0-65535`" + ANSI.ENDC
        print ANSI.RED + "see `sesamum --help` for options." + ANSI.ENDC
        sys.exit(1)

    ip = get_public_ip()
    if ip in configuration.get('main', 'blacklisted_ips').split(','):
        print "%sCurrent public IP (%s) is blacklisted -- see `%s` %s" % (ANSI.RED, ip, config, ANSI.ENDC)
        sys.exit(1)

    update_security_group(conn, profile, region, ip, groups, dry_run)


def get_configuration(file):
    Config = ConfigParser.ConfigParser()
    file = '/'.join([os.getcwd(), file])
    Config.read(file)
    return Config


def get_ec2_connection(region, profile):
    try:
        return boto.ec2.connect_to_region(region, profile_name=profile)
    except Exception as e:
        print ANSI.RED + 'Error establishing ec2 connection -- check your boto configuration' + ANSI.ENDC
        print '  %s' % e.message
    sys.exit(1)


def parse_groups(ports):
    # drop malformed port args, then build up a dict of security groups to operate on
    # {'i-1234567': ['1123', '5813'], 'foo': ['1123']}
    ports = [el for el in ports if ':' in el]
    groups = dict([el.split(':') for el in ports])
    for group in groups:
        groups[group] = groups[group].split(',')
    return groups


def get_public_ip():
    headers = {'User-Agent': 'Lynx/2.8.8dev.3 libwww-FM/2.14 LOL/4.2.0 SSL-MM/1.4.1'}
    return urllib2.urlopen(urllib2.Request('http://checkip.amazonaws.com', None, headers)).read().strip()


def lookup_security_group(conn, label):
    try:
        if re.search('sg-[0-9a-f]{8}', label):
            return conn.get_all_security_groups(group_ids=label)[0]
        else:
            return conn.get_all_security_groups(label)[0]
    except boto.exception.EC2ResponseError as e:
        print ANSI.RED + '%sError locating security group "%s":%s' % (ANSI.RED, label, ANSI.ENDC)
        print '  %s' % e.message
    sys.exit(1)


def list_security_groups(conn):
    security_groups = conn.get_all_security_groups()
    print 'Available security groups in \'%s\' %s:' % (conn.profile_name, conn.region.name)
    for security_group in security_groups:
        print '  -> %s [%s]' % (security_group.name, security_group.id)


def get_port_range(port):
    if '-' in port:
        port = port.split('-')
        return (port[0], port[1])
    else:
        return (port, port)


def add_inbound_rule(security_group, ip_range, port):
    port_from, port_to = get_port_range(port)
    try:
        found = False
        for rule in security_group.rules:
            for cidr_ip in rule.grants:
                if str(cidr_ip) == ip_range and str(rule.from_port) == str(port_from) and str(rule.to_port) == str(port_to):
                    found = True
                    break
        if not found:
            res = security_group.authorize(ip_protocol='tcp', from_port=port_from, to_port=port_to, cidr_ip=ip_range)
    except boto.exception.EC2ResponseError as e:
        print '%sERROR adding %s:%s \n %s' % (ANSI.RED, ip_range, port, ANSI.ENDC)
        print '  %s' % e.message
        return(1)


def revoke_inbound_rule(security_group, ip_range, port):
    port_from, port_to = get_port_range(port)
    try:
        res = security_group.revoke('tcp', port_from, port_to, cidr_ip=ip_range)
    except boto.exception.EC2ResponseError as e:
        print '%sERROR revoking %s : %s \n %s' % (ANSI.RED, ip_range, port, ANSI.ENDC)
        print '  %s' % e.message
        return(1)


def update_security_group(conn, profile, region, ip, groups, dry_run):

    ip_range = '%s/32' % ip

    # apply
    for group in groups:
        security_group = lookup_security_group(conn, group)

        for port in groups[group]:
            msg = ANSI.GREEN + '+' + ANSI.ENDC + ' %s:%s' % (ip_range, port)
            if dry_run:
                print msg + ANSI.PURP + " (dry run)" + ANSI.ENDC
            else:
                print msg
                add_inbound_rule(security_group, ip_range, port)

            for instance in security_group.instances():
                print "  %s [%s]" % (instance.tags['Name'], instance.id)

    # wait
    print '\n' + ANSI.GREEN + 'PRESS `ENTER` TO REVERT' + ANSI.ENDC
    raw_input()

    # revert
    for group in groups:
        security_group = lookup_security_group(conn, group)

        for port in groups[group]:
            msg = ANSI.RED + '-' + ANSI.ENDC + ' %s:%s' % (ip_range, port)
            if dry_run:
                print msg + ANSI.PURP + " (dry run)" + ANSI.ENDC
            else:
                print msg
                revoke_inbound_rule(security_group, ip_range, port)

        for instance in security_group.instances():
            print "  %s [%s]" % (instance.tags['Name'], instance.id)


# cli colors
class ANSI:
    PURP = '\033[95m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
