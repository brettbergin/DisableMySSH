#!/usr/bin/env python3

import argparse

from DisableMySSH.config import Config
from DisableMySSH.logger import Logger
from DisableMySSH.aws import AWS


"""
Hello,

Thanks for reading! This python script is meant to satisfy the requirements for the interview assignment. Please feel to reach out to me via email,
if you have any questions or concerns.

Thanks!
Brett
"""


def main() -> None:
    """This is the main function of the program. It will initialize a
    logger, config, and aws class. Finally, it will invoke the audit of ec2 instances.
    """

    config = Config(aws_region="us-east-1")
    logger = Logger(level="INFO").setup_logging()

    aws = AWS(config=config, logger=logger)

    logger.info("Starting DisableMySSH Audit.")
    aws.audit_ec2_instances(ssh_disabled=config.perform_ssh_remediation())
    logger.info("DisableMySSH is finished.")


if __name__ == "__main__":
    main()
