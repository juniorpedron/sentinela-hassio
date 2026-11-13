"""Captura via SPAN (modo Pi) -- le o espelho e atribui a CADA dispositivo.

A porta espelhada do switch carrega o trafego entre o roteador (gateway) e a
rede. Para cada pacote, o MAC do lado da LAN identifica o dispositivo. A
captura e PASSIVA (so le a copia) e extrai apenas metadados:

  - DNS         quem consultou qual dominio (tipo real: A, AAAA, HTTPS...) e
                o mapa IP -> nome a partir das respostas.
  - DHCP        nome que o aparelho anuncia, classe do fabricante e lista de
                parametros -> identificacao do dispositivo.
  - TLS         SNI do ClientHello (site/servico acessado), em qualquer porta.
  - HTTP        Host e User-Agent (identifica sistema/aparelho).
  - QUIC        inicio de conexao HTTP/3; o nome vem do mapa DNS.
  - TCP         cada conexao nova (SYN) para qualquer porta e o VOLUME de
                cada conexao, medido pelos numeros de sequencia entre o SYN e
                o FIN/RST -- sem precisar ler os pacotes de dados.
  - Entrada     conexao iniciada DE FORA para um aparelho da casa -> alerta.

Limites honestos: volume so de TCP (QUIC/UDP nao entra na conta), conexoes
so entram no volume quando fecham, e conteudo cifrado nunca e lido.

Requer scapy + a interface de captura em modo promiscuo (o run.sh do add-on
configura). O import do scapy roda FORA do event loop (o carregamento do
libpcap pode ser lento) para nao congelar o dashboard.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import threading
import time
from collections import OrderedDict, deque
from typing import Optional

log = logging.getLogger("sentinela.pi_capture")

# Filtro BPF "rico": so pacotes de CONTROLE (baratos), nunca o fluxo de dados.
_TCP_PAYLOAD = "tcp[((tcp[12:1] & 0xf0) >> 2):{n}]"
_BPF_RICO = (
    "udp port 53 or udp port 67 or udp port 68"
    " or (tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) != 0)"
    f" or ({_TCP_PAYLOAD.format(n=1)} = 0x16)"
    f" or (tcp dst port 80 and ({_TCP_PAYLOAD.format(n=4)} = 0x47455420"
    f" or {_TCP_PAYLOAD.format(n=4)} = 0x504f5354))"
    " or (udp dst port 443 and udp[8] & 0xc0 = 0xc0)"
    " or (ip6 and ("
    "(ip6[6] = 6 and ip6[53] & 0x07 != 0)"
    " or (ip6[6] = 6 and ip6[(40 + ((ip6[52] & 0xf0) >> 2)):1] = 0x16)"
    " or (ip6[6] = 17 and ip6[42:2] = 443 and ip6[48] & 0xc0 = 0xc0)))"
)
# Filtro antigo (fallback se o libpcap do host recusar o filtro rico).
_BPF_BASICO = "udp port 53 or tcp port 443 or tcp port 80"

_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
           33: "SRV", 64: "SVCB", 65: "HTTPS", 255: "ANY"}

_PORT_APP = {
    22: "ssh", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 123: "ntp", 143: "imap",
    443: "https", 465: "smtps", 554: "rtsp", 587: "smtp", 853: "dns-tls", 993: "imaps",
    995: "pop3s", 1883: "mqtt", 3478: "stun", 5222: "xmpp", 5223: "apple-push",
    5228: "google-push", 6668: "tuya", 8009: "cast", 8080: "http-alt", 8443: "https-alt",
    8883: "mqtt-tls", 9000: "p2p-camera",
}

_SYN, _FIN, _RST, _ACK = 0x02, 0x01, 0x04, 0x10
_MAX_CONNS = 20000        # conexoes abertas acompanhadas ao mesmo tempo
_CONN_TTL = 6 * 3600      # desiste de uma conexao sem FIN depois disso
_MAX_NAMES = 50000        # mapa IP -> nome (respostas DNS)
_DEDUPE_TTL = 3600        # mesma (dispositivo, destino) so vira 1 registro por hora
_MAX_BPS = 125_000_000    # 1 Gbit/s: teto fisico para validar o volume de uma conexao
_GRANDE = 200_000_000     # acima disso a conexao entra no diagnostico de volume alto


def _fmt_mac(m: Optional[str]) -> Optional[str]:
    if not m:
        return None
    m = m.lower()
    # ignora MACs de grupo/multicast (bit menos significativo do 1o octeto)
    try:
        if int(m.split(":")[0], 16) & 0x01:
            return None
    except ValueError:
        return None
    return m


def _txt(v) -> str:
    if isinstance(v, bytes):
        return v.decode("utf-8", "ignore")
    return str(v)


def parse_http(data: bytes) -> tuple[Optional[str], Optional[str]]:
    """(Host, User-Agent) de uma requisicao HTTP em texto claro."""
    try:
        head = data[:2048].split(b"\r\n\r\n", 1)[0].decode("latin-1", "ignore")
    except Exception:
        return None, None
    linhas = head.split("\r\n")
    if not linhas or not linhas[0].split(" ")[0] in (
        "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT"
    ):
        return None, None
    host = ua = None
    for ln in linhas[1:]:
        k, _, v = ln.partition(":")
        k = k.strip().lower()
        if k == "host":
            host = v.strip().split(":")[0] or None
        elif k == "user-agent":
            ua = v.strip()[:200] or None
    return host, ua


def parse_dhcp_options(options) -> dict:
    """Extrai hostname / classe do fabricante / lista de parametros do DHCP (scapy)."""
    out: dict = {}
    for opt in options or []:
        if not isinstance(opt, tuple) or len(opt) < 2:
            continue
        k, v = opt[0], opt[1]
        if k == "hostname":
            out["dhcp_name"] = _txt(v).strip("\x00 ")[:63] or None
        elif k == "vendor_class_id":
            out["dhcp_vendor"] = _txt(v).strip("\x00 ")[:80] or None
        elif k == "param_req_list":
            vals = opt[1:] if len(opt) > 2 else (v if isinstance(v, (list, tuple, bytes)) else [v])
            try:
                out["dhcp_params"] = ",".join(str(int(x)) for x in vals)[:120]
            except (TypeError, ValueError):
                pass
        elif k == "message-type":
            out["_tipo"] = v
    return out


class Dedupe:
    """Chave vista recentemente? (evita gravar o mesmo destino a cada pacote)."""

    def __init__(self, ttl: float = _DEDUPE_TTL, limite: int = 40000) -> None:
        self._d: dict = {}
        self._ttl = ttl
        self._lim = limite

    def novo(self, chave, agora: Optional[float] = None) -> bool:
        agora = time.monotonic() if agora is None else agora
        t = self._d.get(chave)
        if t is not None and agora - t < self._ttl:
            return False
        if len(self._d) >= self._lim:
            corte = agora - self._ttl
            self._d = {k: v for k, v in self._d.items() if v > corte}
            if len(self._d) >= self._lim:
                self._d.clear()
        self._d[chave] = agora
        return True


class Rastreador:
    """Nucleo da captura: recebe pacotes scapy e produz registros.

    Separado do sniffer para poder ser testado com pacotes sinteticos. As
    saidas vao para callbacks (``emit_*``), que o ``run_forever`` liga ao
    storage. Roda na thread do sniffer; o volume acumulado e protegido por
    lock porque e esvaziado pela task assincrona de flush.
    """

    def __init__(self, layers, net, exclude=(), parse_sni=None) -> None:
        (self.ARP, self.DNS, self.Ether, self.IP, self.IPv6, self.TCP, self.UDP,
         self.BOOTP, self.DHCP) = layers
        self.net = net
        self.exclude = set(exclude or ())
        self.parse_sni = parse_sni
        self.gw_macs: set[str] = set()       # MACs do lado da internet (roteador)
        self.lan_macs: dict[str, str] = {}   # mac -> ultimo IPv4 visto
        self.ip_names: OrderedDict[str, str] = OrderedDict()
        self.conns: OrderedDict[tuple, dict] = OrderedDict()
        self.dd_dns, self.dd_flow, self.dd_in = Dedupe(), Dedupe(), Dedupe(ttl=86400)
        self.meta_vista: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._uso: dict[tuple, list] = {}    # (mac, host, proto) -> [up, down, conns]
        # diagnostico: ultimas conexoes com volume alto (para conferir se a medicao e real)
        self.grandes: deque = deque(maxlen=25)
        self.stats = {"pacotes": 0, "dns": 0, "tls": 0, "http": 0, "quic": 0, "dhcp": 0,
                      "tcp_novas": 0, "tcp_fechadas": 0, "entrada": 0, "erros": 0}
        # callbacks (definidos pelo run_forever / testes)
        self.emit_dns = self.emit_flow = self.emit_meta = self.emit_event = lambda **kw: None

    # ---- helpers ------------------------------------------------------- #
    def _is_lan(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip) in self.net
        except ValueError:
            return False

    def _endpoint(self, pkt):
        """(mac, ip_lan, ip_remoto, saindo) do dispositivo da LAN, ou None."""
        e = pkt.getlayer(self.Ether)
        if e is None:
            return None
        src_mac, dst_mac = _fmt_mac(e.src), _fmt_mac(e.dst)
        if pkt.haslayer(self.IP):
            ip = pkt[self.IP]
            s_lan, d_lan = self._is_lan(ip.src), self._is_lan(ip.dst)
            if s_lan and not d_lan:
                if dst_mac:
                    self.gw_macs.add(dst_mac)
                if src_mac:
                    self.lan_macs[src_mac] = ip.src
                    return src_mac, ip.src, ip.dst, True
            elif d_lan and not s_lan:
                if src_mac:
                    self.gw_macs.add(src_mac)
                if dst_mac:
                    self.lan_macs[dst_mac] = ip.dst
                    return dst_mac, ip.dst, ip.src, False
            elif s_lan and d_lan:
                # trafego interno (ex.: DNS para o roteador e a resposta dele)
                if src_mac and src_mac not in self.gw_macs:
                    self.lan_macs.setdefault(src_mac, ip.src)
                    return src_mac, ip.src, ip.dst, True
                if dst_mac and dst_mac not in self.gw_macs:
                    return dst_mac, ip.dst, ip.src, False
            return None
        if pkt.haslayer(self.IPv6):
            ip6 = pkt[self.IPv6]
            # IPv6: o endereco e publico; quem identifica o aparelho e o MAC,
            # desde que ja o tenhamos visto na LAN por IPv4.
            if src_mac in self.lan_macs and src_mac not in self.gw_macs:
                return src_mac, self.lan_macs[src_mac], ip6.dst, True
            if dst_mac in self.lan_macs and dst_mac not in self.gw_macs:
                return dst_mac, self.lan_macs[dst_mac], ip6.src, False
        return None

    def _nome(self, ip: str) -> Optional[str]:
        return self.ip_names.get(ip)

    def _aprende_nome(self, ip: str, nome: str) -> None:
        self.ip_names[ip] = nome
        self.ip_names.move_to_end(ip)
        if len(self.ip_names) > _MAX_NAMES:
            self.ip_names.popitem(last=False)

    def _soma_uso(self, mac: str, host: str, proto: str, up: int, down: int, conns: int) -> None:
        with self._lock:
            v = self._uso.setdefault((mac, host, proto), [0, 0, 0])
            v[0] += up
            v[1] += down
            v[2] += conns

    def drena_uso(self) -> dict:
        """Entrega e zera o volume acumulado (chamado pela task de flush)."""
        with self._lock:
            uso, self._uso = self._uso, {}
        return uso

    def _meta(self, mac: str, ip: str, **kv) -> None:
        novos = {k: v for k, v in kv.items() if v}
        visto = self.meta_vista.setdefault(mac, {})
        if all(visto.get(k) == v for k, v in novos.items()):
            return
        visto.update(novos)
        self.emit_meta(mac=mac, ip=ip, **novos)

    # ---- entrada ------------------------------------------------------- #
    def processa(self, pkt, agora: Optional[float] = None) -> None:
        """Processa um pacote. Nunca levanta excecao."""
        try:
            self.stats["pacotes"] += 1
            self._processa(pkt, time.monotonic() if agora is None else agora)
        except Exception:
            self.stats["erros"] += 1  # pacote malformado nunca derruba a captura

    def _processa(self, pkt, agora: float) -> None:
        # ---- DHCP: o aparelho se apresenta (antes de ter IP) ----
        if pkt.haslayer(self.DHCP) and pkt.haslayer(self.BOOTP):
            self._dhcp(pkt)
            return

        ep = self._endpoint(pkt)
        if ep is None:
            return
        mac, ip, remoto, saindo = ep
        if mac in self.exclude:           # sensor/IoT excluido da captura profunda
            return

        if pkt.haslayer(self.DNS):
            self._dns(pkt, mac, ip, saindo, agora)
            return
        if pkt.haslayer(self.TCP):
            self._tcp(pkt, mac, ip, remoto, saindo, agora)
            return
        if pkt.haslayer(self.UDP) and saindo and pkt[self.UDP].dport == 443:
            self._quic(pkt, mac, ip, remoto, agora)

    def _dhcp(self, pkt) -> None:
        b = pkt[self.BOOTP]
        if getattr(b, "op", 0) != 1:      # so pedidos do cliente
            return
        raw = bytes(b.chaddr)[:6]
        mac = _fmt_mac(":".join(f"{x:02x}" for x in raw))
        if not mac or mac in self.exclude:
            return
        info = parse_dhcp_options(pkt[self.DHCP].options)
        info.pop("_tipo", None)
        if not info:
            return
        self.stats["dhcp"] += 1
        ip = self.lan_macs.get(mac) or (b.ciaddr if b.ciaddr != "0.0.0.0" else None)
        from sentinela.common.identify import os_from_dhcp

        so = os_from_dhcp(info.get("dhcp_vendor"), info.get("dhcp_params"))
        self._meta(mac, ip, os=so, **info)

    def _dns(self, pkt, mac, ip, saindo, agora) -> None:
        d = pkt[self.DNS]
        if d.qd is None:
            return
        try:
            q0 = d.qd[0] if hasattr(d.qd, "__getitem__") else d.qd
        except Exception:
            q0 = d.qd
        qname = _txt(q0.qname).rstrip(".")
        if not qname:
            return
        if d.qr == 0:
            qtype = _QTYPES.get(int(q0.qtype), str(q0.qtype))
            if saindo and self.dd_dns.novo((mac, qname, qtype), agora):
                self.stats["dns"] += 1
                self.emit_dns(mac=mac, ip=ip, qname=qname, qtype=qtype)
            return
        # resposta: aprende IP -> nome (o nome CONSULTADO, nao o CNAME final)
        n = int(getattr(d, "ancount", 0) or 0)
        rr = d.an
        for i in range(min(n, 30)):
            try:
                r = rr[i] if hasattr(rr, "__getitem__") else rr
            except Exception:
                break
            if r is None:
                break
            if int(getattr(r, "type", 0)) in (1, 28):
                rdata = _txt(getattr(r, "rdata", ""))
                if rdata:
                    self._aprende_nome(rdata, qname)

    def _tcp(self, pkt, mac, ip, remoto, saindo, agora) -> None:
        t = pkt[self.TCP]
        flags = int(t.flags)
        lport, rport = (t.sport, t.dport) if saindo else (t.dport, t.sport)
        chave = (mac, lport, remoto, rport)
        c = self.conns.get(chave)

        if flags & _SYN:
            if not flags & _ACK:
                if saindo:                 # conexao nova: aparelho -> internet
                    self.stats["tcp_novas"] += 1
                    host = self._nome(remoto)
                    self.conns[chave] = {"t": agora, "isn_c": t.seq, "isn_s": None, "host": host,
                                         "up": None, "down": None, "ip": ip, "dport": rport}
                    self.conns.move_to_end(chave)
                    while len(self.conns) > _MAX_CONNS:
                        self.conns.popitem(last=False)
                    if rport not in (80, 443):
                        alvo = host or remoto
                        if self.dd_flow.novo((mac, alvo, rport), agora):
                            self.emit_flow(mac=mac, ip=ip, dst_ip=remoto, dst_port=rport,
                                           proto="tcp", sni=host,
                                           app_proto=_PORT_APP.get(rport, f"tcp/{rport}"))
                elif self._is_lan(remoto) or str(remoto).lower().startswith("fe80"):
                    pass                   # vizinho da propria rede (ex.: o roteador lendo UPnP da TV): nao e entrada
                else:                      # alguem de FORA abrindo conexao para dentro
                    self.stats["entrada"] += 1
                    if self.dd_in.novo((mac, lport), agora):
                        self.emit_event(
                            mac=mac, ip=ip, severity="warning", type="inbound.tcp",
                            title=f"Conexao de entrada vinda da internet (porta {lport})",
                            detail=f"origem {self._nome(remoto) or remoto} -> {ip}:{lport}",
                        )
            elif c is not None and not saindo:
                c["isn_s"] = t.seq         # SYN-ACK do servidor
            return

        # ---- carga util: TLS ClientHello / HTTP ----
        if saindo and pkt.haslayer("Raw"):
            dados = bytes(pkt["Raw"].load)
            if dados[:1] == b"\x16" and self.parse_sni is not None:
                sni = self.parse_sni(dados)
                if sni:
                    self.stats["tls"] += 1
                    if c is not None:
                        c["host"] = sni
                    self._aprende_nome(remoto, sni)
                    if self.dd_flow.novo((mac, sni, rport), agora):
                        self.emit_flow(mac=mac, ip=ip, dst_ip=remoto, dst_port=rport, proto="tcp",
                                       sni=sni, app_proto="https" if rport == 443 else f"tls/{rport}")
            elif rport == 80 or dados[:4] in (b"GET ", b"POST", b"HEAD", b"PUT "):
                host, ua = parse_http(dados)
                if host or ua:
                    self.stats["http"] += 1
                if ua:
                    self._meta(mac, ip, ua=ua)
                if host:
                    if c is not None:
                        c["host"] = host
                    if self.dd_flow.novo((mac, host, rport), agora):
                        self.emit_flow(mac=mac, ip=ip, dst_ip=remoto, dst_port=rport, proto="tcp",
                                       sni=host, app_proto="http")

        # ---- fim da conexao: mede o volume pelos numeros de sequencia ----
        if flags & (_FIN | _RST) and c is not None:
            # Um RST com seq 0 e resposta a segmento sem ACK: o numero nao pertence
            # a conexao e geraria um volume falso de ate 2 GB. So o FIN, ou um RST
            # com seq real, serve para medir.
            mede = bool(flags & _FIN) or t.seq != 0
            if mede and saindo and c["up"] is None and c["isn_c"] is not None:
                c["up"] = (t.seq - c["isn_c"] - 1) & 0xFFFFFFFF
            elif mede and not saindo and c["down"] is None and c["isn_s"] is not None:
                c["down"] = (t.seq - c["isn_s"] - 1) & 0xFFFFFFFF
            if flags & _RST or (c["up"] is not None and c["down"] is not None):
                c["fim"] = ("RST" if flags & _RST else "FIN") + ("/cliente" if saindo else "/servidor")
                c["fim_seq"] = int(t.seq)
                self._fecha(chave, c, agora)

    def _fecha(self, chave, c, agora: Optional[float] = None) -> None:
        self.conns.pop(chave, None)
        up = c["up"] or 0
        down = c["down"] or 0
        # Valores impossiveis sao descartados: acima de 2 GB (seq lixo / volta do
        # contador) ou acima do que a duracao da conexao permitiria a 1 Gbit/s.
        dur = max(1.0, (agora if agora is not None else time.monotonic()) - c["t"])
        teto = min(0x7FFFFFFF, int(dur * _MAX_BPS) + 1_000_000)
        if up > teto:
            up = 0
            self.stats["volume_descartado"] = self.stats.get("volume_descartado", 0) + 1
        if down > teto:
            down = 0
            self.stats["volume_descartado"] = self.stats.get("volume_descartado", 0) + 1
        self.stats["tcp_fechadas"] += 1
        host = c.get("host") or self._nome(chave[2]) or chave[2]
        if up + down >= _GRANDE:
            reg = {"host": host, "porta": c.get("dport"), "up": up, "down": down, "dur_s": round(dur, 1),
                   "fim": c.get("fim", "expirou"), "isn_c": c.get("isn_c"), "isn_s": c.get("isn_s"),
                   "fim_seq": c.get("fim_seq"), "v6": ":" in str(chave[2])}
            self.grandes.append(reg)
            log.info("conexao com volume alto: %s", reg)
        self._soma_uso(chave[0], host, "tcp", up, down, 1)

    def _quic(self, pkt, mac, ip, remoto, agora) -> None:
        dados = bytes(pkt[self.UDP].payload)
        if not dados or not dados[0] & 0x80:      # so cabecalho longo (inicio)
            return
        self.stats["quic"] += 1
        host = self._nome(remoto)
        if self.dd_flow.novo((mac, host or remoto, "quic"), agora):
            self.emit_flow(mac=mac, ip=ip, dst_ip=remoto, dst_port=443, proto="udp",
                           sni=host, app_proto="quic")

    def limpa(self, agora: Optional[float] = None) -> int:
        """Encerra conexoes velhas demais (sem FIN visto). Devolve quantas."""
        agora = time.monotonic() if agora is None else agora
        velhas = [k for k, c in self.conns.items() if agora - c["t"] > _CONN_TTL]
        for k in velhas:
            c = self.conns.get(k)
            if c is not None:
                self._fecha(k, c, agora)
        return len(velhas)


def _filtro_valido(expr: str) -> bool:
    """O libpcap deste host aceita o filtro? (falha -> usamos o basico)."""
    try:
        from scapy.arch.common import compile_filter

        compile_filter(expr, linktype=1)   # 1 = Ethernet (o espelho e Ethernet)
        return True
    except Exception as exc:
        log.warning("filtro BPF rico recusado (%s); usando o basico", exc)
        return False


async def run_forever(storage, settings, controls=None) -> None:
    """Sobe o sniffer no espelho e alimenta o storage por dispositivo."""
    def _importar_scapy():
        from scapy.all import ARP, BOOTP, DHCP, DNS, Ether, IP, IPv6, TCP, UDP, AsyncSniffer
        return (ARP, DNS, Ether, IP, IPv6, TCP, UDP, BOOTP, DHCP), AsyncSniffer

    try:
        loop = asyncio.get_running_loop()
        layers, AsyncSniffer = await asyncio.wait_for(
            loop.run_in_executor(None, _importar_scapy), timeout=30
        )
    except Exception as exc:
        log.warning("scapy/libpcap indisponivel; captura SPAN desligada (%s)", exc)
        return

    from sentinela.sensors.pc_local.sniffer import parse_sni  # reusa o parser de SNI

    iface = settings.capture_iface or "eth1"
    try:
        net = ipaddress.ip_network(settings.lan_cidr, strict=False)
    except ValueError:
        net = ipaddress.ip_network("192.168.0.0/24")

    rast = Rastreador(layers, net, settings.exclude_macs, parse_sni)
    dev_cache: dict[str, str] = {}   # mac -> device_id (evita upsert por pacote)

    async def _dev_id(mac: str, ip: Optional[str]) -> str:
        did = dev_cache.get(mac)
        if did is None:
            did, _new = await storage.upsert_device(mac=mac, ip4=ip)
            dev_cache[mac] = did
        return did

    def _agenda(coro) -> None:
        asyncio.run_coroutine_threadsafe(coro, loop)

    def emit_dns(*, mac, ip, qname, qtype):
        async def _rec():
            did = await _dev_id(mac, ip)
            await storage.record_dns(device_id=did, client_ip=ip, qname=qname,
                                     qtype=qtype, blocked=False)
        _agenda(_rec())

    def emit_flow(*, mac, ip, dst_ip, dst_port, proto, sni, app_proto):
        async def _rec():
            did = await _dev_id(mac, ip)
            await storage.record_flow(device_id=did, src_ip=ip, dst_ip=dst_ip, dst_port=dst_port,
                                      proto=proto, sni=sni, app_proto=app_proto)
        _agenda(_rec())

    def emit_meta(*, mac, ip, **kv):
        async def _rec():
            did = await _dev_id(mac, ip)
            await storage.merge_device_meta(did, **kv)
        _agenda(_rec())

    def emit_event(*, mac, ip, severity, type, title, detail):
        async def _rec():
            did = await _dev_id(mac, ip)
            await storage.add_event(device_id=did, severity=severity, type=type,
                                    title=title, detail=detail)
        _agenda(_rec())

    rast.emit_dns, rast.emit_flow = emit_dns, emit_flow
    rast.emit_meta, rast.emit_event = emit_meta, emit_event

    def prn(pkt) -> None:
        if controls is not None and not getattr(controls, "sniffer_enabled", True):
            return
        rast.processa(pkt)

    filtro = _BPF_RICO if await loop.run_in_executor(None, _filtro_valido, _BPF_RICO) else _BPF_BASICO
    modo = "rico" if filtro is _BPF_RICO else "basico"
    try:
        sniffer = AsyncSniffer(iface=iface, filter=filtro, prn=prn, store=False)
        sniffer.start()
    except Exception as exc:
        log.warning(
            "nao consegui iniciar a captura SPAN em '%s' (%s). Confira o "
            "espelhamento no switch e a interface (CAPTURE_IFACE).", iface, exc,
        )
        return

    if controls is not None:
        controls.capture = {"iface": iface, "filtro": modo, "stats": rast.stats,
                            "gateways": rast.gw_macs, "conexoes_abertas": rast.conns,
                            "nomes_dns": rast.ip_names, "grandes": rast.grandes}

    log.info(
        "captura SPAN ativa em '%s' (LAN=%s; filtro %s; %d MAC(s) excluido(s) da captura)",
        iface, net, modo, len(rast.exclude),
    )

    async def _flush() -> None:
        """A cada 30 s grava o volume acumulado; a cada 10 min limpa conexoes velhas."""
        n = 0
        while True:
            await asyncio.sleep(30)
            n += 1
            try:
                uso = rast.drena_uso()
                linhas = []
                for (mac, host, proto), (up, down, conns) in uso.items():
                    did = await _dev_id(mac, rast.lan_macs.get(mac))
                    linhas.append({"device_id": did, "host": host, "proto": proto,
                                   "bytes_up": up, "bytes_down": down, "conns": conns})
                await storage.add_usage_many(linhas)
                if n % 20 == 0:
                    rast.limpa()
            except Exception as exc:  # o flush nunca derruba a captura
                log.warning("flush do volume falhou: %s", exc)

    flush_task = asyncio.create_task(_flush(), name="span-flush")
    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        log.info("captura SPAN cancelada")
        raise
    finally:
        flush_task.cancel()
        try:
            sniffer.stop()
        except Exception:
            pass
