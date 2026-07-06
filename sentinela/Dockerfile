ARG BUILD_FROM=ghcr.io/home-assistant/aarch64-base-python:3.12-alpine3.18
FROM ${BUILD_FROM}

# Ferramentas de rede: ping/arp (descoberta), iproute2 (modo promiscuo),
# libpcap + tcpdump (captura via scapy no espelho SPAN). Base = Alpine.
RUN apk add --no-cache iputils net-tools iproute2 libpcap tcpdump

WORKDIR /app

# Dependencias (inclui scapy: captura DNS/SNI na interface espelho).
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Codigo do Sentinela (montado por build-addon.py em ./app).
COPY app /app
COPY run.sh /run.sh
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]
