FROM ubuntu:latest

COPY install.sh /tmp/install.sh
COPY requirements.txt /tmp/requirements.txt
RUN cd /tmp/ && /bin/bash install.sh

COPY scripts/ /secLot/

USER root
WORKDIR /secLot/
CMD ["/bin/bash", "start.sh"]