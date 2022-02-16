#!/usr/bin/env python3

import argparse

import boto3


class Config(object):
    def __init__(self, aws_region: str) -> None:
        self.aws_region = aws_region

    def _handle_args(self):
        """This function parses the CLI argugment, and returns the parsed result."""

        parser = argparse.ArgumentParser()
        parser.add_argument(
            "-r", "--remediate", help="Set value to: true | false", required=True
        )
        return parser.parse_args()

    def ec2_client(self) -> boto3.client:
        """This function returns an AWS boto3 client object."""

        return boto3.client("ec2", region_name=self.aws_region)

    def ec2_resource(self) -> boto3.resource:
        """This function returns an AWS boto3 resource object."""

        return boto3.resource("ec2", region_name=self.aws_region)

    def perform_ssh_remediation(self) -> bool:
        """This function is called to determine if the client would like to remediate the ssh open ingress rules."""

        args = self._handle_args()
        return True if args.remediate.lower() == "true" else False
