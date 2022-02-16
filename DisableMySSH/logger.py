#!/usr/bin/env python3

import sys
import logging


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
