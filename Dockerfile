FROM python:2-alpine 
LABEL maintainer="Zetanova <office@zetanova.eu>"

WORKDIR /app

COPY . .

# udp reply port
EXPOSE 61000/udp

ENTRYPOINT [ "python", "tplink_smartplug.py" ]