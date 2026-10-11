"""Visitor and chat-session analytics for the private admin dashboard.

Only metadata is recorded (IP, browser, times, counts). Message content is
end-to-end encrypted and never reaches the server, so it cannot be logged.

Storage: PostgreSQL when DATABASE_URL is set (recommended on Render, whose disk
is wiped on every restart), otherwise SQLite in DATA_DIR.
"""
import os
import re
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import (
    Column, DateTime, Integer, MetaData, String, Table, create_engine, delete, func, insert,
    select, update,
)

RETENTION_DAYS = int(os.environ.get("ANALYTICS_RETENTION_DAYS", "30"))

metadata = MetaData()

visits = Table(
    "visits", metadata,
    Column("id", Integer, primary_key=True),
    Column("ts", DateTime(timezone=True), index=True),
    Column("ip", String(64), index=True),
    Column("forwarded_for", String(300)),
    Column("browser", String(40)),
    Column("os", String(40)),
    Column("device", String(20)),
    Column("user_agent", String(400)),
    Column("referrer", String(300)),
    Column("language", String(80)),
    Column("path", String(200)),
)

chat_sessions = Table(
    "chat_sessions", metadata,
    Column("id", Integer, primary_key=True),
    Column("public_id", String(32), index=True),
    Column("username", String(40)),
    Column("ip", String(64), index=True),
    Column("browser", String(40)),
    Column("os", String(40)),
    Column("device", String(20)),
    Column("user_agent", String(400)),
    Column("connected_at", DateTime(timezone=True), index=True),
    Column("disconnected_at", DateTime(timezone=True)),
    Column("messages_sent", Integer, default=0),
    Column("recipients_total", Integer, default=0),
    Column("username_changes", Integer, default=0),
)

security_events = Table(
    "security_events", metadata,
    Column("id", Integer, primary_key=True),
    Column("ts", DateTime(timezone=True), index=True),
    Column("ip", String(64), index=True),
    Column("kind", String(40)),
    Column("path", String(200)),
    Column("user_agent", String(400)),
)

admin_state = Table(
    "admin_state", metadata,
    Column("key", String(40), primary_key=True),
    Column("value", Integer),
)


def _database_url():
    url = os.environ.get("DATABASE_URL")
    if url:
        # Render/Heroku hand out postgres://; SQLAlchemy wants an explicit driver.
        return re.sub(r"^postgres(ql)?://", "postgresql+psycopg://", url)
    data_dir = os.environ.get("DATA_DIR", os.path.join(os.path.dirname(__file__), "data"))
    os.makedirs(data_dir, exist_ok=True)
    return f"sqlite:///{os.path.join(data_dir, 'analytics.db')}"


engine = create_engine(_database_url(), pool_pre_ping=True)
metadata.create_all(engine)


def now():
    return datetime.now(timezone.utc)


def clip(value, size):
    return (value or "")[:size]


# ---------------------------------------------------------------- user agents

_BROWSERS = [
    ("Edge", r"Edg(e|A|iOS)?/"), ("Opera", r"OPR/|Opera"), ("Samsung Internet", r"SamsungBrowser"),
    ("Firefox", r"Firefox/|FxiOS"), ("Chrome", r"Chrome/|CriOS"), ("Safari", r"Safari/"),
]
_SYSTEMS = [
    ("Android", r"Android"), ("iOS", r"iPhone|iPad|iPod"), ("Windows", r"Windows"),
    ("macOS", r"Mac OS X|Macintosh"), ("ChromeOS", r"CrOS"), ("Linux", r"Linux"),
]
_BOTS = re.compile(r"bot|crawl|spider|slurp|curl|wget|python|httpx|go-http|headless|monitor", re.I)


def parse_user_agent(ua):
    ua = ua or ""
    browser = next((name for name, rx in _BROWSERS if re.search(rx, ua)), "Other")
    system = next((name for name, rx in _SYSTEMS if re.search(rx, ua)), "Other")
    if _BOTS.search(ua):
        device = "Bot"
    elif re.search(r"iPad|Tablet", ua):
        device = "Tablet"
    elif re.search(r"Mobi|iPhone|Android", ua):
        device = "Mobile"
    else:
        device = "Desktop"
    return browser, system, device


# ---------------------------------------------------------------- writes

def record_visit(ip, forwarded_for, user_agent, referrer, language, path):
    browser, system, device = parse_user_agent(user_agent)
    with engine.begin() as conn:
        conn.execute(insert(visits).values(
            ts=now(), ip=clip(ip, 64), forwarded_for=clip(forwarded_for, 300), browser=browser,
            os=system, device=device, user_agent=clip(user_agent, 400), referrer=clip(referrer, 300),
            language=clip(language, 80), path=clip(path, 200),
        ))


def start_chat_session(public_id, username, ip, user_agent):
    browser, system, device = parse_user_agent(user_agent)
    with engine.begin() as conn:
        result = conn.execute(insert(chat_sessions).values(
            public_id=public_id, username=username, ip=clip(ip, 64), browser=browser, os=system,
            device=device, user_agent=clip(user_agent, 400), connected_at=now(),
            messages_sent=0, recipients_total=0, username_changes=0,
        ))
        return result.inserted_primary_key[0]


def end_chat_session(row_id, username, messages_sent, recipients_total, username_changes):
    with engine.begin() as conn:
        conn.execute(update(chat_sessions).where(chat_sessions.c.id == row_id).values(
            disconnected_at=now(), username=username, messages_sent=messages_sent,
            recipients_total=recipients_total, username_changes=username_changes,
        ))


def record_security_event(kind, ip, path, user_agent):
    with engine.begin() as conn:
        conn.execute(insert(security_events).values(
            ts=now(), ip=clip(ip, 64), kind=kind, path=clip(path, 200), user_agent=clip(user_agent, 400),
        ))


def failed_admin_logins_since(ip, since):
    with engine.connect() as conn:
        return conn.execute(
            select(func.count()).select_from(security_events).where(
                security_events.c.ip == ip,
                security_events.c.kind.in_(["admin_login_failed", "decoy_hit", "hidden_form_probe"]),
                security_events.c.ts >= since,
            )
        ).scalar_one()


def admin_epoch():
    """Bumped by "log out all devices"; sessions carrying an older epoch are rejected."""
    with engine.connect() as conn:
        value = conn.execute(select(admin_state.c.value).where(admin_state.c.key == "epoch")).scalar()
    return value or 0


def bump_admin_epoch():
    with engine.begin() as conn:
        current = conn.execute(select(admin_state.c.value).where(admin_state.c.key == "epoch")).scalar()
        if current is None:
            conn.execute(insert(admin_state).values(key="epoch", value=1))
        else:
            conn.execute(update(admin_state).where(admin_state.c.key == "epoch").values(value=current + 1))


_last_purge = 0.0


def purge_old_rows(force=False):
    """Delete analytics older than RETENTION_DAYS (runs at most once per hour)."""
    global _last_purge
    if not force and time.monotonic() - _last_purge < 3600:
        return
    _last_purge = time.monotonic()
    cutoff = now() - timedelta(days=RETENTION_DAYS)
    with engine.begin() as conn:
        conn.execute(delete(visits).where(visits.c.ts < cutoff))
        conn.execute(delete(chat_sessions).where(chat_sessions.c.connected_at < cutoff))
        conn.execute(delete(security_events).where(security_events.c.ts < cutoff))


# ---------------------------------------------------------------- dashboard reads

def _rows(query):
    with engine.connect() as conn:
        return [dict(row._mapping) for row in conn.execute(query)]


def _count(table, column, since, distinct=None):
    target = func.count(func.distinct(distinct)) if distinct is not None else func.count()
    with engine.connect() as conn:
        return conn.execute(select(target).select_from(table).where(column >= since)).scalar_one()


def _top(table, column, since, limit=6):
    query = (
        select(column.label("name"), func.count().label("count"))
        .where(table.c[since[0]] >= since[1])
        .group_by(column).order_by(func.count().desc()).limit(limit)
    )
    return _rows(query)


def dashboard_data():
    day = now() - timedelta(days=1)
    week = now() - timedelta(days=7)
    with engine.connect() as conn:
        messages_week = conn.execute(
            select(func.coalesce(func.sum(chat_sessions.c.messages_sent), 0))
            .where(chat_sessions.c.connected_at >= week)
        ).scalar_one()
    return {
        "stats": {
            "visits_24h": _count(visits, visits.c.ts, day),
            "unique_ips_24h": _count(visits, visits.c.ts, day, distinct=visits.c.ip),
            "unique_ips_7d": _count(visits, visits.c.ts, week, distinct=visits.c.ip),
            "chat_sessions_7d": _count(chat_sessions, chat_sessions.c.connected_at, week),
            "messages_7d": messages_week,
            "security_events_7d": _count(security_events, security_events.c.ts, week),
        },
        "top_browsers": _top(visits, visits.c.browser, ("ts", week)),
        "top_os": _top(visits, visits.c.os, ("ts", week)),
        "top_devices": _top(visits, visits.c.device, ("ts", week)),
        "recent_sessions": _rows(select(chat_sessions).order_by(chat_sessions.c.connected_at.desc()).limit(100)),
        "recent_visits": _rows(select(visits).order_by(visits.c.ts.desc()).limit(100)),
        "security": _rows(select(security_events).order_by(security_events.c.ts.desc()).limit(100)),
    }
