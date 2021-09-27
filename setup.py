#!/usr/bin/env python
# coding=utf-8

import os
import sys
import json
import setuptools
from setuptools.command.test import test as TestCommand

DIRECTORY = os.path.dirname(os.path.realpath(__file__))
SETUP_JSON = None

try:
    with open(os.path.join(DIRECTORY, "setup.json"), "r") as f:
        SETUP_JSON = json.load(f)
except Exception as e:
    print(
        "! Error loading setup.json file in the same directory as setup.py.\n"
        + "  Check your installation."
    )
    print("  Exception: {}".format(e))
    sys.exit(1)


def readme():
    with open(os.path.join(DIRECTORY, "README.md"), encoding='utf-8') as f:
        return f.read()


class PyTest(TestCommand):
    user_options = [("pytest-args=", "a", "Arguments to pass to py.test")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = []

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import pytest

        errno = pytest.main(self.pytest_args)
        sys.exit(errno)


setuptools.setup(
    name=SETUP_JSON["name"],
    version=SETUP_JSON["version"],
    author=", ".join(SETUP_JSON["authors"]),
    author_email=", ".join(SETUP_JSON["emails"]),
    description=SETUP_JSON["description"],
    long_description=readme(),
    long_description_content_type="text/markdown",
    license=SETUP_JSON["license"],
    keywords="",
    url=None,
    namespace_packages=SETUP_JSON["namespace_packages"],
    packages=SETUP_JSON["packages"],
    install_requires=SETUP_JSON["install_requires"],
    tests_require=["pytest"],
    cmdclass={"test": PyTest},
    entry_points=SETUP_JSON["entry_points"],
    classifiers=SETUP_JSON["classifiers"],
    include_package_data=True,
    zip_safe=False,
)
