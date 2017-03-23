#!/usr/bin/env python

from __future__ import print_function

from setuptools import setup

try:
    from pypandoc import convert
    read_md = lambda f: convert(f, 'rst')
except ImportError:
    print('pandoc is not installed.')
    read_md = lambda f: open(f, 'r').read()

setup(name='slicecap',
      version='0.0.1',
      description='Slice a pcap file into pieces and process in parallel',
      long_description=read_md('README.md'),
      author='Keiichi SHIMA',
      author_email='keiichi@iijlab.net',
      url='https://github.com/keiichishima/slicecap/',
      py_modules=['slicecap'],
      install_requires=['future>=0.16.0'],
      entry_points = {
          'console_scripts': ['slicecap=slicecap:main']
      },
      classifiers=[
          'Development Status :: 4 - Beta',
          'Environment :: Console',
          'Intended Audience :: Developers',
          'Intended Audience :: Information Technology',
          'Intended Audience :: Science/Research',
          'Intended Audience :: System Administrators',
          'License :: OSI Approved :: BSD License',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3.6',
          'Topic :: Scientific/Engineering :: Information Analysis',
          'Topic :: System :: Networking',
          'Topic :: Utilities'],
      license='BSD License',
     )
