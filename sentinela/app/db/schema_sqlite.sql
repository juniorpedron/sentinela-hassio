-- Sentinela - Schema SQLite (MODO PC / standalone)
-- Mesmas tabelas do modo Pi, porem:
--   * timestamps como TEXT ISO8601 (sem TIMESTAMPTZ)
--   * sem extensao TimescaleDB / sem hypertable
--   * tudo idempotente (IF NOT EXISTS)
-- Aplicado por SqliteStorage.connect() a cada boot.

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------------
-- device: um registro por dispositivo (casado por MAC).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS device (
    id          TEXT PRIMARY KEY,
    mac         TEXT UNIQUE NOT NULL,
    mac_vendor  TEXT,
    hostname    TEXT,
    ip4         TEXT,
    ip6         TEXT,
    trust_state TEXT NOT NULL DEFAULT 'unknown'
        CHECK (trust_state IN ('unknown', 'trusted', 'quarantine')),
    label       TEXT,
    profile     TEXT NOT NULL DEFAULT 'desconhecido',
    first_seen  TEXT NOT NULL,   -- ISO8601
    last_seen   TEXT NOT NULL    -- ISO8601
);

CREATE INDEX IF NOT EXISTS idx_device_trust_state ON device (trust_state);
CREATE INDEX IF NOT EXISTS idx_device_last_seen   ON device (last_seen DESC);

-- ---------------------------------------------------------------------------
-- flow: fluxos observados (proprio trafego + broadcast/multicast no PC).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS flow (
    ts         TEXT NOT NULL,   -- ISO8601
    device_id  TEXT REFERENCES device (id) ON DELETE SET NULL,
    src_ip     TEXT,
    dst_ip     TEXT,
    src_port   INTEGER,
    dst_port   INTEGER,
    proto      TEXT,
    bytes_up   INTEGER,
    bytes_down INTEGER,
    sni        TEXT,
    ja4        TEXT,
    app_proto  TEXT
);

CREATE INDEX IF NOT EXISTS idx_flow_device_ts ON flow (device_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_flow_ts        ON flow (ts DESC);

-- ---------------------------------------------------------------------------
-- dns_query: consultas DNS (reverse DNS / captura propria no PC).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dns_query (
    ts         TEXT NOT NULL,   -- ISO8601
    device_id  TEXT REFERENCES device (id) ON DELETE SET NULL,
    client_ip  TEXT,
    qname      TEXT,
    qtype      TEXT,
    answer     TEXT,
    blocked    INTEGER NOT NULL DEFAULT 0   -- 0/1 (bool)
);

CREATE INDEX IF NOT EXISTS idx_dns_device_ts ON dns_query (device_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_dns_ts        ON dns_query (ts DESC);
CREATE INDEX IF NOT EXISTS idx_dns_qname     ON dns_query (qname);

-- ---------------------------------------------------------------------------
-- event: eventos/alertas do sistema.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS event (
    ts        TEXT NOT NULL,   -- ISO8601
    device_id TEXT REFERENCES device (id) ON DELETE SET NULL,
    severity  TEXT NOT NULL
        CHECK (severity IN ('info', 'warning', 'critical')),
    type      TEXT NOT NULL,
    title     TEXT NOT NULL,
    detail    TEXT
);

CREATE INDEX IF NOT EXISTS idx_event_device_ts ON event (device_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_event_ts        ON event (ts DESC);
CREATE INDEX IF NOT EXISTS idx_event_severity  ON event (severity);

-- ---------------------------------------------------------------------------
-- ndp: descobertas de camada 2/vizinhanca (ARP snoop / NDP).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ndp (
    ts   TEXT NOT NULL,   -- ISO8601
    mac  TEXT,
    ip   TEXT,
    kind TEXT CHECK (kind IN ('arp', 'na', 'ns', 'ra'))
);

CREATE INDEX IF NOT EXISTS idx_ndp_mac_ts ON ndp (mac, ts DESC);
CREATE INDEX IF NOT EXISTS idx_ndp_ts     ON ndp (ts DESC);

-- ---------------------------------------------------------------------------
-- RETENCAO (modo PC): sem policy nativa. A limpeza — se desejada — segue a
-- mesma regra do Pi (30d conhecido / 180d desconhecido) via DELETE agendado.
-- TODO(sentinela): implementar purga periodica no run_pc (task de manutencao)
-- comparando ts com strftime('now') e device.trust_state.
-- ---------------------------------------------------------------------------
