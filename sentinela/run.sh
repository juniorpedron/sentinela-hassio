#!/usr/bin/with-contenv bashio
# Entrypoint do add-on Sentinela (MODO PI: captura via SPAN, ingress).

IFACE="$(bashio::config 'capture_iface')"
export CAPTURE_IFACE="${IFACE}"
export LAN_CIDR="$(bashio::config 'lan_cidr')"
export RETENTION_PCAP_DAYS="$(bashio::config 'retention_days')"
export SENTINELA_MODE="pi"
export SENTINELA_READONLY="0"
export API_HOST="0.0.0.0"
export API_PORT="8099"                 # porta interna do ingress
export DB_PATH="/data/sentinela.db"    # volume persistente do add-on
export PYTHONPATH="/app"

# Lista de exclusao (array YAML -> csv em EXCLUDE_MACS).
EXCL=""
for m in $(bashio::config 'exclude_macs'); do
  EXCL="${EXCL}${m},"
done
export EXCLUDE_MACS="${EXCL}"

# Poe a interface do espelho em modo PROMISCUO, ativa e sem IP (so recebe copia).
if [ -n "${IFACE}" ]; then
  if ip link set "${IFACE}" up promisc on 2>/dev/null; then
    bashio::log.info "Interface de captura '${IFACE}' em modo promiscuo."
  else
    bashio::log.warning "Nao consegui configurar '${IFACE}'. Confira o nome (ip link) e o cabo no espelho."
  fi
fi

bashio::log.info "Sentinela MODO PI iniciando: iface=${IFACE}, lan='${LAN_CIDR}', excluidos='${EXCLUDE_MACS}', ingress:8099"
exec python -m sentinela.sensors.pi_span.run_pi
