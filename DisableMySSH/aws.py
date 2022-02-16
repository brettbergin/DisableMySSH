#!/usr/bin/env python3

from .config import Config
from .logger import Logger


class AWS(object):
    def __init__(self, config: Config, logger: Logger) -> None:
        self.config = config
        self.logger = logger

        self.ec2_client = self.config.ec2_client()
        self.ec2_resource = self.config.ec2_resource()

    def _check_for_ingress_violations(self, ip_perms: list) -> bool:
        """This function iterates over all ip permissions in a group, and evaluates them for the case of 0.0.0.0:22.
        If found, we increment a count from 0. If said count results in a number greater than zero, we return True.
        """

        violation_count = 0

        for perm in ip_perms:

            # Only returns and ingress rule that has a 0.0.0.0 ingress.
            ip_ranges = [ip for ip in perm["IpRanges"] if ip["CidrIp"] == "0.0.0.0/0"]

            # Ensures the from_port is 22 and that we have at least on record in our ip_ranges list.
            # If no element exists in our ip_ranges list, then we dont have an ingress rule matching our condition.
            if perm.get("FromPort") == 22 and len(ip_ranges) > 0:
                violation_count += 1

        return True if violation_count > 0 else False

    def _inspect_instance_security_groups(self, groups: list) -> list:
        """This function iterates over all the security groups attached to an instance, and checks for violations.
        If found, the security group object is appended into a list of affected groups, and returned.
        """

        group_violations = []

        for group_id in groups:
            try:
                sec_group = self.ec2_resource.SecurityGroup(id=group_id)

            except Exception as err:
                self.logger.error(
                    f"Unable to create a security group object using SG ID: {group_id}. Error: {err}."
                )
                continue

            group_has_violations = self._check_for_ingress_violations(
                ip_perms=sec_group.ip_permissions
            )

            if group_has_violations:
                group_violations.append(sec_group)

        return group_violations

    def audit_ec2_instances(self, ssh_disabled: bool) -> bool:
        """This function is the entrypoint to invoke the audit of our ec2 instances and their security groups.
        The function downloads a list of ec2 instances from the AWS API, and evaluates their security group ingress rules.

        If found that the instance has a security group with an ingress rule matching a 0.0.0.0 ingress with a from port of 22,
        we will attempt to revoke said ingress.
        """

        self.logger.info(f"Security Group ingress revocation: {ssh_disabled}.")

        try:
            response = self.ec2_client.describe_instances()

        except Exception as err:
            self.logger.error(
                f"Unable to fetch list of AWS EC2 instances. Error: {err}."
            )
            return False

        # Parses and flattens all instances from the response from AWS API.
        reservations = [i["Instances"] for i in response["Reservations"]]
        instances = [
            instance for reservation in reservations for instance in reservation
        ]

        err_count = 0
        for instance in instances:
            # Returns a list of security groups that are attached to this instance
            # that have groups with ingress rules that have a CIDR of 0.0.0.0 with a from_port of 22.
            affected_instance_groups = self._inspect_instance_security_groups(
                groups=[grp["GroupId"] for grp in instance["SecurityGroups"]]
            )

            self.logger.info(
                f"Instance: {instance['InstanceId']} has {len(affected_instance_groups)} security groups with ingress violation(s)."
            )

            # If the instance doesnt have any security groups found with ingress violations, we move to the next instance.
            if not len(affected_instance_groups) > 0:
                continue

            # At this point we have found security groups with ingress violations.
            for group in affected_instance_groups:
                self.logger.info(
                    f"!!! Found affected instance: {instance['InstanceId']} where group {group.group_name} has port 22 allowed from 0.0.0.0."
                )

                # If the ssh disable configuration has been set to true, we will revoke the ingress on said group.
                if ssh_disabled:
                    self.logger.info(
                        f"Attempting To Revoke SSH Ingress From 0.0.0.0 For Security Group: {group.group_id}."
                    )

                    try:
                        group.revoke_ingress(
                            CidrIp="0.0.0.0/0", FromPort=22, ToPort=22, IpProtocol="tcp"
                        )
                    except Exception as err:
                        self.logger.error(
                            f"Unable to revoke ingress for SG: {group.group_id}. Error: {err}."
                        )
                        err_count += 1

        return True if err_count == 0 else False
