FROM ubuntu:22.04@sha256:74f92a6b3589aa5cac6028719aaac83de4037bad4371ae79ba362834389035aa

RUN apt-get update && apt-get install socat sudo -yqq \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /task

COPY ./flag.txt /tmp
COPY ./server.sh /
COPY binary ./

EXPOSE 1337
ENTRYPOINT /server.sh
