#!/usr/bin/env python3
# coding=utf-8

from setuptools import setup

setup(name='python-ppnetwork',
    py_modules = ["pp_link","pp_flow","pp_control"],
    author='gonewind.he',
      author_email='gonewind.he@gmail.com',
      maintainer='gonewind',
      maintainer_email='gonewind.he@gmail.com',
      url='https://github.com/gonewind73/ppnetwork',
      description='Linux/Windows  ppnetwork driver  written in  python',
      long_description=open('README.rst',encoding="utf-8").read(),
#       long_description_content_type="text/markdown",
      version='1.0.6',
      python_requires='>=3',
      platforms=["Linux","Windows"],
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: MIT License',
          'Programming Language :: Python :: 3',
          'Topic :: Software Development :: Libraries :: Python Modules',
          'Topic :: System :: Networking'])
