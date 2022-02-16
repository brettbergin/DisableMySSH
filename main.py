#!/usr/bin/env python3

import os
import sys
import logging
import argparse

import boto3


class Logger(object):
    def __init__(self, level: str) -> None:
        self.logger = logging.getLogger()
        self.log_level = level

    def setup_logging(self) -> logging.getLogger():
        """
        This function creates and customized a logging object we will use throughout the application.
        """

        logging.getLogger("boto3").setLevel(logging.CRITICAL)
        logging.getLogger("botocore").setLevel(logging.CRITICAL)
        logging.getLogger("urllib3").setLevel(logging.CRITICAL)

        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] [%(lineno)s: %(funcName)s] %(message)s"
            )
        )
        self.logger.addHandler(handler)

        if self.log_level.upper() == "ERROR":
            self.logger.setLevel(logging.ERROR)

        elif self.log_level.upper() == "DEBUG":
            self.logger.setLevel(logging.DEBUG)

        else:
            self.logger.setLevel(logging.INFO)

        return self.logger


class Config(object):
    def __init__(self, aws_region):
        self.aws_region = aws_region

    def _handle_args(self):
        """ This function parses the CLI argugment, and returns the parsed result. """

        parser = argparse.ArgumentParser()
        parser.add_argument(
            "-r", "--remediate", help="Set value to: true | false", required=True
        )
        return parser.parse_args()

    def ec2_client(self):
        """ This function returns an AWS boto3 client object. """

        return boto3.client("ec2", region_name=self.aws_region)

    def ec2_resource(self):
        """ This function returns an AWS boto3 resource object. """

        return boto3.resource("ec2", region_name=self.aws_region)

    def perform_ssh_remediation(self):
        """
        This function is called to determine if the client would like to remediate the ssh open ingress rules.
        """

        args = self._handle_args()
        return True if args.remediate.lower() == "true" else False


class AWS(object):
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger

        self.ec2_client = self.config.ec2_client()
        self.ec2_resource = self.config.ec2_resource()

    def _check_for_ingress_violations(self, ip_perms):
        """
        This function iterates over all ip permissions in a group, and evaluates them for the case of 0.0.0.0:22.
        If found, we increment a count from 0. If said count results in a number greater than zero, we return True."""

        violation_count = 0

        for perm in ip_perms:
            
            # Only returns and ingress rule that has a 0.0.0.0 ingress.
            ip_ranges = [ip for ip in perm["IpRanges"] if ip["CidrIp"] == "0.0.0.0/0"]

            # Ensures the from_port is 22 and that we have at least on record in our ip_ranges list.
            # If no element exists in our ip_ranges list, then we dont have an ingress rule matching our condition.
            if perm["FromPort"] == 22 and len(ip_ranges) > 0:
                violation_count += 1

        return True if violation_count > 0 else False

    def _inspect_instance_security_groups(self, groups):
        """
        This function iterates over all the security groups attached to an instance, and checks for violations.
        If found, the security group object is appended into a list of affected groups, and returned. """

        group_violations = []

        for group_id in groups:
            sec_group = self.ec2_resource.SecurityGroup(id=group_id)
            group_has_violations = self._check_for_ingress_violations(
                ip_perms=sec_group.ip_permissions
            )

            if group_has_violations:
                group_violations.append(sec_group)

        return group_violations

    def audit_ec2_instances(self, ssh_disabled):
        """ This function is the entrypoint to invoke the audit of our ec2 instances and their security groups.
        The function downloads a list of ec2 instances from the AWS API, and evaluates their security group ingress rules.

        If found that the instance has a security group with an ingress rule matching a 0.0.0.0 ingress with a from port of 22, 
        we will attempt to revoke said ingress.
        """

        self.logger.info(f"Security Group ingress revocation: {ssh_disabled}.")

        response = self.ec2_client.describe_instances()
        reservations = [i["Instances"] for i in response["Reservations"]]
        instances = [
            instance for reservation in reservations for instance in reservation
        ]

        for instance in instances:
            # Returns a list of security groups that are attached to this instance 
            # that have groups with ingress rules that have a CIDR of 0.0.0.0 with a from_port of 22.
            affected_instance_groups = self._inspect_instance_security_groups(
                groups=[grp["GroupId"] for grp in instance["SecurityGroups"]]
            )

            self.logger.debug(
                f"Instance: {instance['InstanceId']} has {len(affected_instance_groups)} security groups with ingress violations."
            )

            # If the instance doesnt have any security groups found with ingress violations, we move to the next instance.
            if not len(affected_instance_groups) > 0:
                continue

            # At this point we have found security groups with ingress violations.
            for group in affected_instance_groups:
                self.logger.info(f"Instance: {instance['InstanceId']} has group: {group.group_name} with an open ssh ingress from 0.0.0.0.")
                
                # If the ssh disable configuration has been set to true, we will revoke the ingress on said group.
                if ssh_disabled:
                    self.logger.info(f"Revoking Ingress For Group: {group.group_id}.")
                    group.revoke_ingress(
                        CidrIp="0.0.0.0/0", FromPort=22, ToPort=22, IpProtocol="tcp"
                    )


def main():
    """ This is the main function of the program. It will initialize a logger, config, and aws class. 
    Finally, it will invoke the audit of ec2 instances. """

    logger = Logger(level="DEBUG").setup_logging()
    config = Config(aws_region=os.environ["AWS_REGION"])
    aws = AWS(config=config, logger=logger)

    logger.info("Starting DisableMySSH Audit.")
    aws.audit_ec2_instances(ssh_disabled=config.perform_ssh_remediation())
    logger.info("DisableMySSH is finished.")


if __name__ == "__main__":
    main()
