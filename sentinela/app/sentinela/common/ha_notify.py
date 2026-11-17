"""Aviso de "aparelho novo na rede" para o Home Assistant (webhook local).

O Sentinela chama um webhook do Home Assistant quando aparece um aparelho que
ele nunca viu. Quem decide o que fazer (notificar o celular, etc.) e uma
automacao do HA. Nada sai da rede local: o destino padrao e o proprio HA em
``127.0.0.1:8123``.

Cuidados para nao virar spam:
  - espera alguns minutos antes de avisar, para o nome (DHCP) e o tipo
    chegarem e para o agrupamento de MACs reconhecer um aparelho ja conhecido
    que so trocou de MAC privado;
  - nao avisa de aparelho ja rotulado/classificado, nem de endereco fora da LAN;
  - no maximo ``LIMITE_POR_HORA`` avisos por hora (banco vazio no primeiro uso).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import time
import urllib.request
from typing import Any, Optional

from sentinela.common import identify

log = logging.getLogger("sentinela.ha_notify")

ESPERA_S = 180.0
LIMITE_POR_HORA = 6
_ID_OK = re.compile(r"^[A-Za-z0-9_-]{8,128}$")


def url_do_webhook(valor: Optional[str]) -> Optional[str]:
    """Aceita o id do webhook (vira URL local do HA) ou uma URL http(s) completa."""
    v = (valor or "").strip()
    if not v or v.lower() == "null":
        return None
    if v.lower().startswith(("http://", "https://")):
        return v
    if _ID_OK.match(v):
        return f"http://127.0.0.1:8123/api/webhook/{v}"
    return None


def montar_aviso(devs: list[dict], device_id: str, lan_net: Any = None) -> Optional[dict]:
    """Decide se o registro ``device_id`` merece aviso; devolve o conteudo ou None."""
    aparelhos, mapa = identify.agrupar(devs)
    raiz = mapa.get(device_id)
    ap = next((a for a in aparelhos if a["id"] == raiz), None)
    if ap is None:
        return None
    if len(ap.get("members") or []) > 1:
        return None                      # aparelho ja conhecido, so mudou de MAC
    if ap.get("label") or (ap.get("trust_state") or "unknown") != "unknown":
        return None                      # ja classificado pelo usuario
    e = identify.enrich(ap, lan_net)
    if e["internal"] or not (e.get("ip4") or e.get("ip6")):
        return None
    return {
        "type": "device.new",
        "id": ap["id"],
        "name": e["display_name"],
        "kind": e["kind_label"],
        "ip": e.get("ip4") or e.get("ip6") or "",
        "mac": e.get("mac") or "",
        "vendor": e.get("mac_vendor") or "",
        "os": e.get("os") or "",
        "private_mac": bool(e["private_mac"]),
        "first_seen": e.get("first_seen") or "",
    }


def _post(url: str, corpo: dict) -> None:
    data = json.dumps(corpo, default=str).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=5).read()


class AvisoNovos:
    """Listener do storage: agenda o aviso de cada dispositivo novo."""

    def __init__(self, storage: Any, url: str, lan_cidr: Optional[str] = None,
                 espera_s: float = ESPERA_S, enviar=_post) -> None:
        self.storage = storage
        self.url = url
        self.espera_s = espera_s
        self.enviar = enviar
        self.enviados = 0
        self.descartados = 0
        self._momentos: list[float] = []
        self._tarefas: set = set()
        try:
            self.lan_net = ipaddress.ip_network(lan_cidr, strict=False) if lan_cidr else None
        except ValueError:
            self.lan_net = None

    def __call__(self, msg: dict) -> None:
        if msg.get("kind") != "device":
            return
        device_id = (msg.get("payload") or {}).get("id")
        if not device_id:
            return
        t = asyncio.ensure_future(self._tratar(device_id))
        self._tarefas.add(t)
        t.add_done_callback(self._tarefas.discard)

    def _dentro_do_limite(self) -> bool:
        agora = time.monotonic()
        self._momentos = [m for m in self._momentos if agora - m < 3600]
        if len(self._momentos) >= LIMITE_POR_HORA:
            return False
        self._momentos.append(agora)
        return True

    async def _tratar(self, device_id: str) -> None:
        try:
            await asyncio.sleep(self.espera_s)
            aviso = montar_aviso(await self.storage.list_devices(), device_id, self.lan_net)
            if aviso is None:
                return
            if not self._dentro_do_limite():
                self.descartados += 1
                log.warning("aviso de aparelho novo descartado (limite por hora): %s", aviso["name"])
                return
            await asyncio.get_running_loop().run_in_executor(None, self.enviar, self.url, aviso)
            self.enviados += 1
            log.info("aviso de aparelho novo enviado ao Home Assistant: %s", aviso["name"])
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # um aviso nunca derruba o coletor
            log.warning("aviso de aparelho novo falhou: %s", exc)
