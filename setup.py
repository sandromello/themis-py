#!/usr/bin/env python
from distutils.core import setup
from ConfigParser import ConfigParser
#from setuptools import setup

packages = { 
'themis_package' : {
      'name' : 'themis',
      'version' : '0.1',
      'author' : 'Sandro Mello',
      'author_email' : 'sandromll@gmail.com',
      'url' : 'https://github.com/sandromello/themis',
      'description' : 'Core tools for themis',
      'packages' : ['themis'],
      'package_dir' : {'themis' : 'src/lib'}
  },
'themis_web_package' :  {
      'name' : 'themis-web',
      'version' : '0.1',
      'author' : 'Sandro Mello',
      'author_email' : 'sandromll@gmail.com',
      'url' : 'https://github.com/sandromello/themis',
      'description' : 'API and web access for themis',
      'data_files' : [
        ('sbin', ['src/sbin/tmsprov'])
      ]
  },
'themis_core_package' : {
    'name' : 'themis-core',
    'version' : '0.1',
    'author' : 'Sandro Mello',
    'author_email' : 'sandromll@gmail.com',
    'url' : 'https://github.com/sandromello/themis',
    'description' : 'Milter rate limit for postfix',
    'data_files' : [
        ('/etc/themis', ['src/config/config.yaml']),
        ('/etc/init.d', ['src/init.d/themis']),
        ('/opt/themis/plugins', ['src/plugins/learning.py'])
      ]
  }
}

config = ConfigParser()
config.readfp(open('themisbuild.cfg'))
build_package = config.get('main', 'build')

setup(**packages[build_package])