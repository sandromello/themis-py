Themis
======

###The personification of divine order, law, and custom###

Milter rate limiter for postfix

[Read the Docs](http://themis.rtfd.org)

Building documentation...

# Utils
http://milter-manager.sourceforge.net/reference/introduction.html
http://packages.debian.org/search?keywords=python-redis

# Build Ubuntu 14.04
pip install stdeb
Change setup.py target and then:
python setup.py --command-packages=stdeb.command debianize
rm -rf debian/source
debuild -us -uc -I
