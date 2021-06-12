#!/usr/bin/env python
# coding: utf-8
import sys
from setuptools import setup, find_packages


install_requires = [
    'ecdsa>=0.10',
    'six>=1.5.2',
    'websocket-client==0.15.0'
]


setup(
    name="stmpy_lib",
    version="0.1.2",
    author="stm-open",
    author_email="open@labs.stream",
    url="https://github.com/stm-open/stmpy.git",
    description="Python lib for the STM network",
    license='BSD',
    packages=find_packages(),
    zip_safe=True,
    install_requires=install_requires,
)
