FROM ubuntu:20.04

RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
      apt-get -y install -y ca-certificates libssl1.1 

ADD ./geth /app/geth
ENTRYPOINT /app/geth
