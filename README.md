# Themis

Themis is a flexible milter, build on top of [pymilter](http://pythonhosted.org/pymilter) that strictly control your postfix environment. The main goal of this project is not only having control the users, but also to provide useful information about your mail environment. 

## What does it do?

#### 1) Control all the flow of connections in policies

With this kind of control, you could create flexible policies for each connection, separing logic of MTA behaviors. E.G.: Inbound, Outbound policies 

#### 2) Rate limiting of messages

Flexible, you could assign several limits by message

#### 3) Predict rate of messages sent - unstable

The idea is to predict the behavior of a messages sent by each user and have limits by timeframes of time. E.G.: 1min, 5min, 10min, ...

#### 4) SPF check

Use pyspf for checking spf of senders, you can control how these messages are handled with policies features

#### 5) Match headers and assign new ones

If you have another system that insert headers in messages, you could match then and assign new ones

#### 6) Monitoring

Track the total of connections that are handled and for each policy too.

## Features

- Rate limit
- SPF support
- Header inclusion
- Monitoring: block rated objects, sent messages and connections
- Policies by pool servers
- Dynamic resync of configuration
- Smart rate limiting
- Rate limiting counting by recipients
- Bypass or block by rated object

## Quick Start - Ubuntu 14.04 - ppa not ready yet

Supposing that you have an environment with Zimbra, follow the 2nd step to put themis on route

```
sudo add-apt-repository -y ppa:sandro-mello/themis
sudo apt-get install -y themis-core themis
sudo apt-get install -y redis-server
tmscli -a --policy default Source any Destination any
tail -f /var/log/themis/themisd.log
```

**On Zimbra Server**

```
postconf -e milter_default_action=accept
zmprov ms $(zmhostname) zimbraMtaSmtpdMilters 'inet:themis_server:8440'
zmprov ms $(zmhostname) zimbraMtaNonSmtpdMilters 'inet:themis_server:8440'
zmmtactl restart
```

This will configure a new policy and monitor every sent and receive message on the Zimbra server.


## Build Ubuntu 14.04 - incomplete

```
pip install stdeb
```

Change setup.py target and then:

```
python setup.py --command-packages=stdeb.command debianize
rm -rf debian/source
debuild -us -uc -I
```
