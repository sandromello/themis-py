# CentOS - themis-core
fpm --license Apache2.0 -a x86_64 -n themis-core -m 'Sandro Mello <sandromll@gmail.com>' -d PyYAML -d python-netaddr -d 'python-redis >= 2.8' -d 'numpy >= 1.6' --no-python-dependencies -s python -t rpm themis-core

# CentOS - themis
git clone https://github.com/sandromello/themis-py.git && cd themis-py
make clean && make

# PyPi upload
python setup.py sdist upload -r pypi

# ~/.pypirc
[distutils] # this tells distutils what package indexes you can push to
index-servers = pypi

[pypi] # authentication details for live PyPI
repository: https://pypi.python.org/pypi
username: *******
password: *******

# Ubuntu 14.04

## Import pgp key
gpg --allow-secret-key-import --import sandro_pgp.key

## Change package to build
vim setup.py
python setup.py --command-packages=stdeb.command debianize
rm -rf debian/source

## Fix version
vim debian/changelog
debuild -S -rfakeroot -k47538A93

## Send to ppa
dput ppa:sandro-mello/themis themis_0.1-1_source.changes
