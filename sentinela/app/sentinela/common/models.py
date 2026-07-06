"""Modelos de dados (dataclasses) do Sentinela.

Espelham o esquema compartilhado entre o modo Pi (Postgres/TimescaleDB) e o
modo PC (SQLite). Servem como contrato leve entre storage, sensores e API.
Os timestamps sao representados como str ISO8601 para uniformidade entre os
dois bancos (no SQLite nao ha tipo nativo de timestamp).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# Estados de confianca validos para um dispositivo.
TRUST_STATES = ("unknown", "trusted", "quarantine")
# Severidades validas de evento.
SEVERITIES = ("info", "warning", "critical")
# Tipos de registro NDP/ARP.
NDP_KINDS = ("arp", "na", "ns", "ra")


@dataclass
class Device:
    """Dispositivo observado na rede (chaveado por MAC)."""

    id: str
    mac: str
    mac_vendor: Optional[str] = None
    hostname: Optional[str] = None
    ip4: Optional[str] = None
    ip6: Optional[str] = None
    trust_state: str = "unknown"  # unknown | trusted | quarantine
    label: Optional[str] = None
    profile: str = "desconhecido"
    first_seen: Optional[str] = None  # ISO8601
    last_seen: Optional[str] = None   # ISO8601


@dataclass
class Flow:
    """Fluxo de rede (conexao/agregado) de um dispositivo."""

    ts: str  # ISO8601
    device_id: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    proto: Optional[str] = None
    bytes_up: int = 0
    bytes_down: int = 0
    sni: Optional[str] = None
    ja4: Optional[str] = None
    app_proto: Optional[str] = None


@dataclass
class DnsQuery:
    """Consulta DNS observada (resolver do Pi ou captura local)."""

    ts: str  # ISO8601
    device_id: Optional[str] = None
    client_ip: Optional[str] = None
    qname: Optional[str] = None
    qtype: Optional[str] = None
    answer: Optional[str] = None
    blocked: bool = False


@dataclass
class Event:
    """Evento/alerta gerado pelo sistema."""

    ts: str  # ISO8601
    severity: str  # info | warning | critical
    type: str
    title: str
    device_id: Optional[str] = None
    detail: Optional[str] = None


@dataclass
class Ndp:
    """Registro de vizinhanca (ARP/NDP) coletado por snooping."""

    ts: str  # ISO8601
    mac: str
    ip: str
    kind: str  # arp | na | ns | ra
