FROM debian:8

COPY 'docker/apt/*.gpg' /etc/apt/
COPY 'docker/apt/*.list' /etc/apt/sources.list.d/

RUN apt-key add /etc/apt/ankalagon.gpg \
    && apt-key add /etc/apt/wallarm.gpg \
    && apt-get update \
    && apt-get install -y ruby gem

RUN apt-get update && apt-get -y install dnsutils curl ruby-dev gcc g++ make \
    && gem install ruby-gumbo therubyracer rspec digest-crc net-http-rest_client

RUN apt-get update

RUN gem install rkelly-fixed

COPY ./docker/launch_compose_tests.sh /opt/scanner-extensions/docker/launch_compose_tests.sh

COPY ./ /opt/scanner-extensions

WORKDIR /opt/scanner-extensions

CMD rspec -c
