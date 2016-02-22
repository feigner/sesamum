#!/usr/bin/env python

import argparse
import boto.ec2
import ConfigParser
import os
import re
import sys
import urllib2


# cli colors
class ANSI:
    PURP = '\033[95m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'


def get_args():
    parser = argparse.ArgumentParser(
            description='Using your public IP, temporarily poke holes in an EC2 security group',
            epilog='Example: sesamum.py -r us-east-1 -a production foo:22,443 bar:0-65535')
    parser.add_argument('-d', '--dryrun', default=False, action='store_true')
    parser.add_argument('-r', '--region', default='us-west-2')
    parser.add_argument('-p', '--profile', default='staging')
    parser.add_argument('-l', '--list', action='store_true')
    parser.add_argument('ports', nargs='*')
    return parser.parse_args()


def get_configuration(file):
    Config = ConfigParser.ConfigParser()
    file = '/'.join([os.getcwd(), file])
    Config.read(file)
    return Config


def get_public_ip():
    headers = {'User-Agent': 'Lynx/2.8.8dev.3 libwww-FM/2.14 LOL/4.2.0 SSL-MM/1.4.1'}
    return urllib2.urlopen(urllib2.Request('http://checkip.amazonaws.com', None, headers )).read().strip()


def lookup_security_group(conn, label):
    try:
        if re.search('sg-[0-9a-f]{8}', label):
            return conn.get_all_security_groups(group_ids=label)[0]
        else:
            return conn.get_all_security_groups(label)[0]
    except boto.exception.EC2ResponseError as e:
        print 'Error locating security group "%s"' % label
        print 'Error: %s' % e
    sys.exit(1)


def list_security_groups(conn):
    security_groups = conn.get_all_security_groups()
    print '\nAvailable security groups in \'%s\' %s:' % (conn.profile_name, conn.region.name)
    for security_group in security_groups:
        print '   -> %s : %s' % (security_group.name, security_group.id)


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
        print 'ERROR adding %s : %s \n %s' % (ip_range, port, e)
        return(1)


def revoke_inbound_rule(security_group, ip_range, port):
    port_from, port_to = get_port_range(port)
    try:
        res = security_group.revoke('tcp', port_from, port_to, cidr_ip=ip_range)
    except boto.exception.EC2ResponseError as e:
        print 'ERROR revoking %s : %s \n %s' % (ip_range, port, e)
        return(1)

def update_security_group(conn, profile, region, ip, groups, dry_run=False):

    ip_range = '%s/32' % ip

    for group in groups:
        security_group = lookup_security_group(conn, group)
        instances = security_group.instances()
        for instance in instances:
            print "\n%s [%s]" % (instance.tags['Name'], instance.id)
            for port in groups[group]:
                msg = ANSI.GREEN + '  +' + ANSI.ENDC + ' %s:%s' % (ip_range, port)
                if dry_run:
                    print msg + ANSI.PURP + " (dry run)" + ANSI.ENDC
                else:
                    print msg
                    add_inbound_rule(security_group, ip_range, port)

    print '\n' + ANSI.GREEN + 'PRESS `ENTER` TO REVERT RULES' + ANSI.ENDC
    raw_input()

    for group in groups:
        security_group = lookup_security_group(conn, group)
        instances = security_group.instances()

        for instance in instances:
            print "%s [%s]" % (instance.tags['Name'], instance.id)
            for port in groups[group]:
                msg = ANSI.RED + '  -' + ANSI.ENDC + ' %s:%s' % (ip_range, port)
                if dry_run:
                    print msg + ANSI.PURP + " (dry run)" + ANSI.ENDC
                else:
                    print msg
                    revoke_inbound_rule(security_group, ip_range, port)


if __name__ == '__main__':

    print ANSI.PURP + " ___  ___ ___  __ _ _ __ ___  _   _ _ __ ___"
    print "/ __|/ _ / __|/ _` | '_ ` _ \| | | | '_ ` _ \\"
    print "\__ |  __\__ | (_| | | | | | | |_| | | | | | |"
    print "|___/\___|___/\__,_|_| |_| |_|\__,_|_| |_| |_|" + ANSI.ENDC

    args = get_args()
    configuration = get_configuration('sesamum.conf')
    conn = boto.ec2.connect_to_region(args.region, profile_name=args.profile)

    if args.list:
        list_security_groups(conn)
        sys.exit(0)

    # drop malformed port args, then build up a dict of security groups to operate on
    args.ports[:] = [el for el in args.ports if ':' in el]
    groups = dict([el.split(':') for el in args.ports])
    for group in groups:
        groups[group] = groups[group].split(',')

    if len(groups) < 1:
        print ANSI.RED + "\nPlease specify one or more security groups + ports to operate on" + ANSI.ENDC
        sys.exit(1)

    ip = get_public_ip()
    if ip in configuration.get('main', 'blacklisted_ips').split(','):
        print ANSI.RED + "\nCurrent public IP (%s) is blacklisted -- see `sesamum.conf` %s" % (ip, ANSI.ENDC)
        sys.exit(1)

    update_security_group(conn, args.profile, args.region, ip, groups, args.dryrun)
