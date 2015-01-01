#!/usr/bin/env python
from distutils.core import setup

packages = { 
'themis_core_package' : {
      'name' : 'themis-core',
      'version' : '0.1',
      'author' : 'Sandro Mello',
      'author_email' : 'sandromll@gmail.com',
      'url' : 'https://github.com/sandromello/themis-py',
      'description' : 'Core themis library',
      'long_description' : 'Themis Core Tools is responsible for providing helper functions for themis',
      'packages' : ['themis'],
      'package_dir' : {'themis' : 'src/themis'},
      'data_files' : [
        ('sbin', ['src/sbin/tmscli'])
      ]
  },
'themis_package' : {
    'name' : 'themis',
    'version' : '0.1',
    'author' : 'Sandro Mello',
    'author_email' : 'sandromll@gmail.com',
    'url' : 'https://github.com/sandromello/themis-py',
    'description' : 'Postfix milter behavior rate limiter',
    'long_description' : 'Themis is a policy daemon to predict and control the rate of sending mails in Postfix. \
      Is designed for large scale mail hosting environments, build on top of the python-milter API. \
      The features was built not only for rate limiting but also to provide useful information about your mail environment.'
    'data_files' : [
        ('/etc/themis', ['src/config/config.yaml']),
        ('/etc/init.d', ['src/init.d/themisd']),
        ('sbin', ['src/themismilter.py']),
        ('/var/log/themis', [])
      ]
  }
}

core = 'themis_core_package'
tms = 'themis_package'
setup(**packages[core])
