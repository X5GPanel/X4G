# xhttp_siz10.py
# ══════════════════════════════════════════════════════════════════════════════
# Siz10b · XHTTP Ultra Transport — بازنویسی ساختاری
#   همون رفتار روی سیم (packet-up / stream-up، relay_vless دست‌نخورده،
#   _QuotaGate تطبیقی، _AdaptiveFlow با AIMD)، اما دیگه state سشن یک dict
#   شل نیست: یک کلاس XhttpSession با متدهای خودش، و یک SessionManager
#   که جای دیکشنری/لاک/ریپر سراسری رو می‌گیره. هندلرهای route فقط
#   orchestration هستن؛ منطق ذخیره/باز کردن تونل/تدوین داخل خودِ session است.
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import secrets
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import StreamingResponse

from main import (
    LINKS,
    LINKS_LOCK,
    stats,
    hourly_traffic,
    connections,
    error_logs,
    logger,
    is_link_allowed,
    is_ip_allowed,
    save_state,
)
from relay_vless import parse_vless_header, check_and_use
from speed_limit import throttle

router = APIRouter()

XHTTP_BUF = 512 * 1024
DOWNLINK_QUEUE_MAX = 512
SESSION_IDLE_TIMEOUT = 30
REAPER_INTERVAL = 10
TCP_CONNECT_TIMEOUT = 10.0

# ── تنظیمات موتور تطبیقی (بدون تغییر نسبت به siz10a) ─────────────────────────
SOCK_BUF_SIZE = 2 * 1024 * 1024

FLOW_MIN_HW = 256 * 1024
FLOW_MAX_HW = 16 * 1024 * 1024
FLOW_START_HW = 2 * 1024 * 1024
FLOW_FAST_DRAIN_MS = 2.0
FLOW_SLOW_DRAIN_MS = 25.0

QUOTA_MIN_BATCH = 32 * 1024
QUOTA_MAX_BATCH = 1 * 1024 * 1024
QUOTA_START_BATCH = 64 * 1024
QUOTA_CHECK_INTERVAL = 0.2

PACKET_UP_HIGH_WATER = 2 * 1024 * 1024  # packet-up کوتای batched نداره، همون drain ساده

FINGERPRINTS = {
    "chrome": {
        "content-type": "application/grpc",
        "cache-control": "no-cache, no-store",
        "x-accel-buffering": "no",
        "server": "cloudflare",
    },
    "plain": {
        "content-type": "application/octet-stream",
        "cache-control": "no-store",
        "x-accel-buffering": "no",
    },
}
DEFAULT_FINGERPRINT = "chrome"


def _resp_headers(fp: str) -> dict:
    return dict(FINGERPRINTS.get(fp, FINGERPRINTS[DEFAULT_FINGERPRINT]))


def _tune_socket(writer: asyncio.StreamWriter):
    """TCP_NODELAY + بافرهای بزرگ‌تر سوکت برای کاهش سربار سیستم‌عامل روی ترافیک بالا."""
    sock = writer.transport.get_extra_info("socket")
    if not sock:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCK_BUF_SIZE)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCK_BUF_SIZE)
    except OSError:
        pass


def _req_client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "نامشخص"


# ══════════════════════════════ موتور تطبیقی (بدون تغییر منطق) ══════════════════════════════
class QuotaGate:
    """
    نرخ واقعی هر سشن رو با EWMA اندازه می‌گیره و batch چک کوتا رو زنده تنظیم می‌کنه:
    سشن پرسرعت → batch بزرگ‌تر (await کمتر)، سشن کم‌ترافیک → batch کوچیک (قطع سریع‌تر
    اگه کوتا تموم شده). داده هیچ‌وقت نگه داشته نمی‌شه، فقط لحظه‌ی چک adaptive هست.
    """
    __slots__ = ("uuid", "pending", "last_check", "ok", "batch_bytes", "rate_ewma")

    def __init__(self, uuid: str):
        self.uuid = uuid
        self.pending = 0
        self.last_check = time.monotonic()
        self.ok = True
        self.batch_bytes = QUOTA_START_BATCH
        self.rate_ewma = 0.0

    async def add(self, nbytes: int) -> bool:
        if not self.ok:
            return False
        self.pending += nbytes
        now = time.monotonic()
        elapsed = now - self.last_check
        if self.pending >= self.batch_bytes or elapsed >= QUOTA_CHECK_INTERVAL:
            flush, self.pending = self.pending, 0
            if elapsed > 0:
                inst_rate = flush / elapsed
                self.rate_ewma = inst_rate if self.rate_ewma == 0 else (0.7 * self.rate_ewma + 0.3 * inst_rate)
                target = int(self.rate_ewma * QUOTA_CHECK_INTERVAL)
                self.batch_bytes = max(QUOTA_MIN_BATCH, min(QUOTA_MAX_BATCH, target or QUOTA_MIN_BATCH))
            self.last_check = now
            self.ok = await check_and_use(self.uuid, flush)
            return self.ok
        return True

    async def flush(self) -> bool:
        if self.pending:
            flush, self.pending = self.pending, 0
            self.ok = self.ok and await check_and_use(self.uuid, flush)
        return self.ok


class AdaptiveFlow:
    """
    high-water تطبیقی برای drain(), رفتار AIMD مثل TCP congestion control:
    drain سریع → additive increase سقف بافر؛ drain کند (backpressure واقعی) →
    multiplicative decrease فوری. هر سشن نمونه‌ی جدای خودش رو داره.
    """
    __slots__ = ("high_water", "last_drain_ms")

    def __init__(self):
        self.high_water = FLOW_START_HW
        self.last_drain_ms = 0.0

    def should_drain(self, buf_size: int) -> bool:
        return buf_size > self.high_water

    async def drain(self, writer: asyncio.StreamWriter):
        t0 = time.monotonic()
        await writer.drain()
        elapsed_ms = (time.monotonic() - t0) * 1000
        self.last_drain_ms = elapsed_ms
        if elapsed_ms < FLOW_FAST_DRAIN_MS:
            self.high_water = min(FLOW_MAX_HW, int(self.high_water * 1.5) + 65536)
        elif elapsed_ms > FLOW_SLOW_DRAIN_MS:
            self.high_water = max(FLOW_MIN_HW, self.high_water // 2)


# ══════════════════════════════ Session ══════════════════════════════
@dataclass
class XhttpSession:
    """
    یک سشن XHTTP با همه‌ی state و رفتارش. جای دیکشنری شل قبلی رو می‌گیره؛
    باز کردن تونل، پمپ دانلینک و تدوین همه متد خودِ کلاس‌اند تا هندلرهای
    route فقط orchestration باشن.
    """
    uuid: str
    mode: str
    session_id: str
    conn_id: str
    ip: str

    down_q: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(maxsize=DOWNLINK_QUEUE_MAX))
    writer: Optional[asyncio.StreamWriter] = None
    downlink_task: Optional[asyncio.Task] = None
    last_seen: float = field(default_factory=time.time)
    tcp_open: bool = False
    closed: bool = False

    # فقط packet-up استفاده می‌کنه (سورت seqهای زودرس)
    seq_buf: dict = field(default_factory=dict)
    next_seq: int = 0

    # فقط stream-up استفاده می‌کنه، لازی ساخته می‌شن
    gate: Optional[QuotaGate] = None
    flow: Optional[AdaptiveFlow] = None

    def touch(self):
        self.last_seen = time.time()

    def gate_for_stream(self) -> QuotaGate:
        if self.gate is None:
            self.gate = QuotaGate(self.uuid)
        return self.gate

    def flow_for_stream(self) -> AdaptiveFlow:
        if self.flow is None:
            self.flow = AdaptiveFlow()
        return self.flow

    async def open_tcp(self, first_chunk: bytes) -> asyncio.StreamWriter:
        """هدر VLESS رو پارس می‌کنه، تونل TCP رو باز می‌کنه و پمپ دانلینک رو راه می‌اندازه."""
        command, address, port, payload = await parse_vless_header(first_chunk)
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port), timeout=TCP_CONNECT_TIMEOUT
        )
        _tune_socket(writer)
        if payload:
            writer.write(payload)
            await writer.drain()

        self.writer = writer
        self.tcp_open = True
        logger.info(f"connect XHTTP[{self.mode}] [{self.session_id[:8]}] -> {address}:{port}")
        self.downlink_task = asyncio.create_task(self._pump_downlink(reader))
        asyncio.create_task(save_state())
        return writer

    async def _pump_downlink(self, reader: asyncio.StreamReader):
        first = True
        gate = QuotaGate(self.uuid)  # دانلینک هم از همون گیت batched استفاده می‌کنه
        try:
            while True:
                data = await reader.read(XHTTP_BUF)
                if not data:
                    break
                if not await gate.add(len(data)):
                    break
                await throttle(self.uuid, len(data))
                conn = connections.get(self.conn_id)
                if conn:
                    conn["bytes"] += len(data)
                payload = (b"\x00\x00" + data) if first else data
                first = False
                await self.down_q.put(payload)
        except (asyncio.CancelledError, Exception):
            pass
        finally:
            await gate.flush()
            await SESSIONS.teardown(self.session_id)

    async def downstream_gen(self):
        try:
            while True:
                chunk = await self.down_q.get()
                if chunk is None:
                    break
                self.touch()
                yield chunk
        finally:
            pass

    async def close(self):
        self.closed = True
        if self.downlink_task:
            self.downlink_task.cancel()
            try:
                await self.downlink_task
            except (asyncio.CancelledError, Exception):
                pass
        if self.writer:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass
        connections.pop(self.conn_id, None)
        try:
            self.down_q.put_nowait(None)
        except Exception:
            pass


# ══════════════════════════════ SessionManager ══════════════════════════════
class SessionManager:
    """جایگزین xhttp_sessions/XHTTP_LOCK/_reaper سراسری قبلی."""

    def __init__(self):
        self._sessions: dict[str, XhttpSession] = {}
        self._lock = asyncio.Lock()
        self._reaper_started = False

    async def get_or_create(self, uuid: str, mode: str, session_id: str, ip: str) -> XhttpSession:
        async with self._lock:
            sess = self._sessions.get(session_id)
            if sess is not None:
                sess.touch()
                return sess

            async with LINKS_LOCK:
                link = LINKS.get(uuid)
            if not is_ip_allowed(link, uuid, ip):
                logger.warning(f"🚫 XHTTP[{mode}] rejected uuid={uuid[:8]} ip={ip} (ip limit reached)")
                raise HTTPException(status_code=403, detail="ip limit reached")

            conn_id = secrets.token_urlsafe(6)
            connections[conn_id] = {
                "uuid": uuid,
                "ip": ip,
                "connected_at": datetime.now().isoformat(),
                "bytes": 0,
                "transport": f"xhttp-{mode}",
            }
            sess = XhttpSession(uuid=uuid, mode=mode, session_id=session_id, conn_id=conn_id, ip=ip)
            self._sessions[session_id] = sess
            logger.info(f"new XHTTP[{mode}] session [{session_id[:8]}] uuid={uuid[:8]} ip={ip}")
            return sess

    async def teardown(self, session_id: str):
        async with self._lock:
            sess = self._sessions.pop(session_id, None)
        if not sess:
            return
        await sess.close()
        logger.info(f"closed XHTTP[{sess.mode}] [{session_id[:8]}] total={len(self._sessions)}")

    async def _reap_loop(self):
        while True:
            await asyncio.sleep(REAPER_INTERVAL)
            now = time.time()
            async with self._lock:
                stale = [
                    sid for sid, s in self._sessions.items()
                    if now - s.last_seen > SESSION_IDLE_TIMEOUT and not s.tcp_open
                ]
            for sid in stale:
                await self.teardown(sid)

    def ensure_reaper(self):
        if not self._reaper_started:
            asyncio.create_task(self._reap_loop())
            self._reaper_started = True


SESSIONS = SessionManager()


async def _check_link(uuid: str):
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
    if not is_link_allowed(link):
        raise HTTPException(status_code=403, detail="not authorized")


# ══════════════════════════════ GET دانلینک (مشترک بین دو مد) ══════════════════════════════
@router.get("/xhttp-siz10/{mode}/{uuid}/{session_id}")
async def xhttp_downlink(mode: str, uuid: str, session_id: str, request: Request):
    SESSIONS.ensure_reaper()
    if mode not in ("packet-up", "stream-up"):
        raise HTTPException(status_code=404, detail="unknown mode")
    await _check_link(uuid)
    fp = request.query_params.get("fp", DEFAULT_FINGERPRINT)
    sess = await SESSIONS.get_or_create(uuid, mode, session_id, _req_client_ip(request))
    if sess.closed:
        raise HTTPException(status_code=404, detail="session closed")

    headers = _resp_headers(fp)
    return StreamingResponse(sess.downstream_gen(), headers=headers, media_type=headers["content-type"])


# ══════════════════════════════ PACKET-UP (آپلینک با seq) ══════════════════════════════
@router.post("/xhttp-siz10/packet-up/{uuid}/{session_id}/{seq}")
async def packet_up_upload(uuid: str, session_id: str, seq: int, request: Request):
    SESSIONS.ensure_reaper()
    sess = await SESSIONS.get_or_create(uuid, "packet-up", session_id, _req_client_ip(request))
    if sess.closed:
        raise HTTPException(status_code=404, detail="session closed")

    sess.touch()
    body = await request.body()
    if not body:
        return {"ok": True}

    if not await check_and_use(uuid, len(body)):
        await SESSIONS.teardown(session_id)
        raise HTTPException(status_code=403, detail="quota/disabled/unknown")
    await throttle(uuid, len(body))

    stats["total_requests"] += 1
    connections[sess.conn_id]["bytes"] += len(body)

    try:
        if sess.writer is None:
            # اولین پکتی که حاوی هدر VLESS است، می‌تونه seq=0 نباشه اگر پکت‌ها
            # خارج از ترتیب برسن؛ seq_buf برای سورت کردن seqهای زودرس.
            if seq != 0:
                sess.seq_buf[seq] = body
                return {"ok": True, "buffered": True}

            await sess.open_tcp(body)
            nxt = 1
            while nxt in sess.seq_buf:
                pending = sess.seq_buf.pop(nxt)
                sess.writer.write(pending)
                nxt += 1
            sess.next_seq = nxt
            return {"ok": True, "connected": True}

        if seq == sess.next_seq:
            sess.writer.write(body)
            sess.next_seq += 1
            while sess.next_seq in sess.seq_buf:
                pending = sess.seq_buf.pop(sess.next_seq)
                sess.writer.write(pending)
                sess.next_seq += 1
        else:
            sess.seq_buf[seq] = body

        if sess.writer.transport.get_write_buffer_size() > PACKET_UP_HIGH_WATER:
            await sess.writer.drain()
    except Exception as exc:
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        await SESSIONS.teardown(session_id)
        raise HTTPException(status_code=502, detail="write failed")

    return {"ok": True}


# ══════════════════════════════ STREAM-UP (یک POST پیوسته) ══════════════════════════════
# موتور تطبیقی: QuotaGate (batch کوتا بر اساس نرخ واقعی) + AdaptiveFlow (AIMD روی
# high-water درین). هیچ داده‌ای بافر/coalesce نمی‌شه — هر بایت فوری write() می‌شه،
# فقط «کِی صبر کنیم برای drain» تطبیقیه.
@router.post("/xhttp-siz10/stream-up/{uuid}/{session_id}")
async def stream_up_upload(uuid: str, session_id: str, request: Request):
    SESSIONS.ensure_reaper()
    sess = await SESSIONS.get_or_create(uuid, "stream-up", session_id, _req_client_ip(request))
    if sess.closed:
        raise HTTPException(status_code=404, detail="session closed")

    gate = sess.gate_for_stream()
    flow = sess.flow_for_stream()
    conn = connections[sess.conn_id]  # یک بار لوک‌آپ، نه هر چانک

    try:
        async for chunk in request.stream():
            if not chunk:
                continue
            sess.touch()

            if not await gate.add(len(chunk)):
                raise HTTPException(status_code=403, detail="quota/disabled/unknown")
            await throttle(uuid, len(chunk))

            stats["total_requests"] += 1
            conn["bytes"] += len(chunk)

            if sess.writer is None:
                await sess.open_tcp(chunk)
                continue

            sess.writer.write(chunk)
            if flow.should_drain(sess.writer.transport.get_write_buffer_size()):
                await flow.drain(sess.writer)
    except HTTPException:
        await gate.flush()
        await SESSIONS.teardown(session_id)
        raise
    except Exception as exc:
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        await gate.flush()
        await SESSIONS.teardown(session_id)
        raise HTTPException(status_code=502, detail="stream error")

    await gate.flush()
    return {"ok": True}
