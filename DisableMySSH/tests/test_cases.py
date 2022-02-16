#!/usr/bin/env python3

import sys
import logging
import unittest

from DisableMySSH.config import Config
from DisableMySSH.logger import Logger
from DisableMySSH.aws import AWS


class TestDisableMySSH(unittest.TestCase):
    config = Config(aws_region="us-east-1")
    logger = Logger("ERROR").setup_logging()
    aws = AWS(config=config, logger=logger)

    def test_logging_setup(self):
        self.assertIsInstance(self.logger, logging.RootLogger)

    def test_config_setup(self):
        self.assertIsInstance(self.config, Config)

    def test_init_aws(self):
        self.assertIsInstance(self.aws, AWS)

    def test_aws_instance_audit(self):
        resulting_bool = self.aws.audit_ec2_instances(ssh_disabled=False)
        self.assertIsInstance(resulting_bool, bool)

    def test_ingress_violation_check(self):
        test_input = [
            {
                "FromPort": 22,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0",
                        "Description": "SSH From 0.0.0.0"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 22,
                "UserIdGroupPairs": [],
            },
            {
                "FromPort": 443,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0",
                        "Description": "https From 0.0.0.0"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 443,
                "UserIdGroupPairs": [],
            },
        ]
        result = self.aws._check_for_ingress_violations(ip_perms=test_input)
        self.assertEqual(result, True)

    def test_inspect_instance_sec_groups(self):
        security_groups = self.aws.ec2_client.describe_security_groups()
        all_sec_group_ids = [
            grp["GroupId"]
            for grp in security_groups["SecurityGroups"]
            if grp["GroupName"] != "default"
        ]

        result = self.aws._inspect_instance_security_groups(
            groups=all_sec_group_ids)
        self.assertIsInstance(result, list)
