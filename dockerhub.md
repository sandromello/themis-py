## What is Themis

Themis is a policy daemon to predict and control the rate of sending mails in Postfix. Is designed for large scale mail hosting environments, build on top of the python-milter API. The features was built not only for rate limiting but also to provide useful information about your mail environment.

##How to use this image

### On CentOS

Disable selinux

    setenforce 0

### start a themis instance

    docker run --name themismilter -e "THEMIS_REDIS=192.168.2.100" sandromello/themis themismilter.py

The environment variable `THEMIS_REDIS` should contain the host or ip of the redis server. `THEMIS_REDISPASSWD` could be set to if the redis instance is protected by password.

### start with custom custom config

    wget https://raw.githubusercontent.com/sandromello/themis-py/master/src/config/config.yaml && mv config.yaml /tmp
    docker run --name themismilter -v /tmp:/etc/themis sandromello/themis themismilter.py

Note that, if a custom config is in use, the environment variables should not be set, use the custom config file instead.

### Using tmscli

    docker run -v /tmp:/etc/themis sandromello/themis tmscli

Only works using with custom config to set the redis server

### Docker options
`-d` could be used to send the daemon to background, `--net host` will bind to the host port

### Tested with
- CentOS 7 Minimal
- Ubuntu 14.04
