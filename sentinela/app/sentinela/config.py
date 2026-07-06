"""Configuracao central do Sentinela.

Le variaveis de ambiente (com suporte a .env via python-dotenv) e expoe
as configuracoes atraves de :class:`Settings` / :func:`get_settings`.

Seguro por padrao: a API liga em 127.0.0.1 e, se o ADMIN_TOKEN nao for
fornecido, um token aleatorio e gerado e registrado no log (nunca fica
hardcoded no codigo).
"""

from __future__ import annotations

import logging
import os
import secrets
import socket
from dataclasses import dataclass, field
from functools import lru_cache

try:
    # Carrega variaveis de um arquivo .env, se existir (opcional).
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover - python-dotenv e dependencia declarada
    pass

logger = logging.getLogger("sentinela.config")


def _env(name: str, default: str | None = None) -> str | None:
    """Le uma variavel de ambiente, tratando string vazia como ausente."""
    valor = os.environ.get(name)
    if valor is None or valor.strip() == "":
        return default
    return valor.strip()


def _env_int(name: str, default: int) -> int:
    """Le uma variavel de ambiente como inteiro, com fallback ao default."""
    valor = _env(name)
    if valor is None:
        return default
    try:
        return int(valor)
    except ValueError:
        logger.warning("Valor invalido para %s=%r; usando default %d", name, valor, default)
        return default


@dataclass
class Settings:
    """Configuracoes efetivas do Sentinela (modo Pi ou PC)."""

    #: Modo de operacao: "pi" (completo) ou "pc" (standalone). Default: pc.
    mode: str = "pc"

    #: DSN do Postgres/TimescaleDB (usado no modo Pi).
    db_url: str | None = None

    #: Caminho do arquivo SQLite (usado no modo PC).
    db_path: str = "./sentinela.db"

    #: Host de escuta da API. Padrao seguro: apenas loopback.
    api_host: str = "127.0.0.1"

    #: Porta da API/dashboard.
    api_port: int = 8787

    #: Interface de captura (NIC promiscua no Pi; captura opcional no PC).
    capture_iface: str | None = None

    #: Faixa da LAN para varredura ativa (ping sweep, etc.).
    lan_cidr: str = "192.168.0.0/24"

    #: Servidor DNS upstream (recursao no Technitium).
    dns_upstream: str | None = None

    #: Retencao de PCAP em dias.
    retention_pcap_days: int = 7

    #: Token para mutacoes (header X-Sentinela-Token). Gerado se ausente.
    admin_token: str = field(default="")

    #: MAC do gateway da rede de casa (onde as acoes ativas sao permitidas).
    home_gateway_mac: str | None = None
    #: Somente-leitura: 'auto' (por rede) | '1' (forcado) | '0' (nunca).
    readonly: str = "auto"

    #: URL de webhook para alertas (eventos warning/critical). Opcional.
    alert_webhook: str | None = None

    #: MACs excluidos da CAPTURA profunda (sensores/IoT). Continuam no
    #: inventario, mas sem gravar DNS/SNI. Vem de EXCLUDE_MACS (csv).
    exclude_macs: tuple[str, ...] = ()



def _auto_lan_cidr() -> str:
    """Deriva o CIDR /24 da interface ativa (evita varrer a rede errada ao trocar de rede)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        o = ip.split(".")
        if len(o) == 4:
            return f"{o[0]}.{o[1]}.{o[2]}.0/24"
    except OSError:
        pass
    return "192.168.0.0/24"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Constroi (e cacheia) as configuracoes a partir do ambiente.

    Se ADMIN_TOKEN nao estiver definido, gera um token aleatorio e o
    registra no log para que o operador possa usa-lo nas mutacoes.
    """
    mode = (_env("SENTINELA_MODE", "pc") or "pc").lower()
    if mode not in ("pi", "pc"):
        logger.warning("SENTINELA_MODE=%r invalido; usando 'pc'", mode)
        mode = "pc"

    admin_token = _env("ADMIN_TOKEN")
    if not admin_token:
        admin_token = secrets.token_urlsafe(32)
        logger.warning(
            "ADMIN_TOKEN nao definido; gerado token aleatorio para esta sessao: %s",
            admin_token,
        )

    settings = Settings(
        mode=mode,
        db_url=_env("DB_URL"),
        db_path=_env("DB_PATH", "./sentinela.db"),
        api_host=_env("API_HOST", "127.0.0.1"),
        api_port=_env_int("API_PORT", 8787),
        capture_iface=_env("CAPTURE_IFACE"),
        lan_cidr=_env("LAN_CIDR") or _auto_lan_cidr(),
        dns_upstream=_env("DNS_UPSTREAM"),
        retention_pcap_days=_env_int("RETENTION_PCAP_DAYS", 7),
        admin_token=admin_token,
        alert_webhook=_env("ALERT_WEBHOOK"),
        home_gateway_mac=_env("HOME_GATEWAY_MAC", "24:a5:2c:7b:5d:87"),
        readonly=(_env("SENTINELA_READONLY", "auto") or "auto").lower(),
        exclude_macs=tuple(
            m.strip().lower().replace("-", ":")
            for m in (_env("EXCLUDE_MACS", "") or "").split(",")
            if m.strip()
        ),
    )
    return settings
