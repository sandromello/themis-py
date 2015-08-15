FROM python:2.7
RUN mkdir -p /opt/themis
WORKDIR /opt/themis
ADD requirements.txt /opt/themis/
RUN pip install -r /opt/themis/requirements.txt
CMD ["/bin/bash"]
