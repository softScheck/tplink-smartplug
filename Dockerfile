FROM python:2-alpine 
LABEL maintainer="Zetanova <office@zetanova.eu>"

RUN mkdir /usr/src/app

WORKDIR /usr/src/app

COPY ./tplink_smartplug.py ./tplink_smartplug.py

ENTRYPOINT [ "python", "tplink_smartplug.py" ]