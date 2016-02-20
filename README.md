# SESAMUM

Temporarily poke holes in AWS EC2 security groups!

I work from a number of different locations. Manually adding a cafe's / hotel's / bar's IP to a security group gets tiresome. Wouldn't it be nice to let a script do the work?

Inspired by [cli-ec2-allow-pub-ip](https://github.com/jgraglia/cli-ec2-allow-pub-ip), this tool will temporarily add your public IP to an EC2 security group, then revoke it when you're done doing whatever it is you need to do.

## Requirements

* Python 2.x
* [Boto](https://github.com/boto/boto)
* [Virtualenv 13.1+](https://virtualenv.readthedocs.org/en/latest/)

## Installation

	virtualenv env
	./env/bin/pip install -r requirements.txt

Note: Boto requires your AWS secret key in `~/.boto` or `~/.aws/credentials` -- see [the docs](http://docs.pythonboto.org/en/latest/boto_config_tut.html) for more info.

## Configuration
Sesamum reads a single configuration file located in the repo root, `sesamum.conf`

Configuration options:

* `blacklisted_ips` - comma separated list of IP addresses for which script should refuse to make changes on AWS. 

## Usage

List all security groups using the default region / profile

	sesamum.py --list

List all security groups for the specified region / profile

	sesamum.py --region=us-east-2 --profile=production --list

Dryrun open port 5432 on the `database` security group

	sesamum.py --dryrun database:5432

Open ports 4505 through 4506 on the `sg-1123581` security group, but for reals

	sesamum.py sg-1123581:4505-4506

Mix and match.

	sesamum.py sg-1123581:4505-4506 database:5432 control:22