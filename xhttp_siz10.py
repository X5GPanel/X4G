    نسخه‌ی تطبیقی: به‌جای await check_and_use() به‌ازای هر چانک، و به‌جای یک آستانه‌ی
    ثابت، نرخ واقعی ترافیک هر سشن رو با EWMA اندازه می‌گیره و اندازه‌ی batch رو زنده
    تنظیم می‌کنه (بین QUOTA_MIN_BATCH و QUOTA_MAX_BATCH).
    """

    def __init__(self, link_name: str, client_ip: str):
        self.link_name = link_name
        self.client_ip = client_ip
        self.batch_size = QUOTA_START_BATCH
        self.pending = 0
        self.last_check = time.monotonic()
        self.bytes_since_last_check = 0
        self.ewma_rate = 0.0

    async def consume(self, length: int):
        now = time.monotonic()
        dt = now - self.last_check
        self.pending += length
        self.bytes_since_last_check += length

        # اگر زمان چک رسیده یا مقدار پندینگ از اندازه بَچ بیشتر شده
        if dt >= QUOTA_CHECK_INTERVAL or self.pending >= self.batch_size:
            # ۱. کسر کوتا از سیستم اصلی
            ok = await check_and_use(self.link_name, self.pending, self.client_ip)
            if not ok:
                raise HTTPException(status_code=403, detail="Quota exceeded or link disabled")

            # ۲. به‌روزرسانی EWMA برای محاسبه نرخ ترافیک (بایت بر ثانیه)
            if dt > 0.001:
                inst_rate = self.bytes_since_last_check / dt
                self.ewma_rate = 0.7 * self.ewma_rate + 0.3 * inst_rate if self.ewma_rate > 0 else inst_rate

            # ۳. تنظیم تطبیقی اندازه بَچ بر اساس نرخ ترافیک (هدف: ~200ms بین چک‌ها)
            target_batch = int(self.ewma_rate * QUOTA_CHECK_INTERVAL)
            self.batch_size = max(QUOTA_MIN_BATCH, min(QUOTA_MAX_BATCH, target_batch))

            # ریست شمارنده‌ها
            self.pending = 0
            self.bytes_since_last_check = 0
            self.last_check = now


class _AdaptiveFlow:
    """
    کنترل جریان تطبیقی (AIMD) روی بافر Downlink برای جلوگیری از ایجاد Backpressure
    و بهینه‌سازی سرعت دانلود متناسب با توان پردازشی کلاینت.
    """

    def __init__(self, queue: asyncio.Queue):
        self.queue = queue
        self.high_water = FLOW_START_HW
        self.low_water = self.high_water // 2

    def adjust(self, drain_time_ms: float):
        if drain_time_ms < FLOW_FAST_DRAIN_MS:
            # رشد خطی high-water در صورت سرعت بالای کلاینت
            self.high_water = min(FLOW_MAX_HW, int(self.high_water + 128 * 1024))
        elif drain_time_ms > FLOW_SLOW_DRAIN_MS:
            # کاهش ضربی (AIMD) در صورت کندی کلاینت یا ایجاد Backpressure
            self.high_water = max(FLOW_MIN_HW, int(self.high_water * 0.7))

        self.low_water = self.high_water // 2

    async def wait_if_full(self, current_bytes: int):
        if current_bytes >= self.high_water:
            while current_bytes > self.low_water:
                await asyncio.sleep(0.005)
                current_bytes = self.queue.qsize() * XHTTP_BUF


class XHTTPSession:
    """مدیریت سشن‌های فعال XHTTP"""

    def __init__(self, session_id: str, link_name: str, client_ip: str):
        self.session_id = session_id
        self.link_name = link_name
        self.client_ip = client_ip
        self.downlink_queue = asyncio.Queue(maxsize=DOWNLINK_QUEUE_MAX)
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.last_active = time.monotonic()
        self.closed = False
        self.flow_control = _AdaptiveFlow(self.downlink_queue)
        self.quota_gate = _QuotaGate(link_name, client_ip)

    def touch(self):
        self.last_active = time.monotonic()

    async def close(self):
        if self.closed:
            return
        self.closed = True
        if self.writer:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass


async def _session_reaper():
    """پاکسازی سشن‌های منقضی شده به‌صورت دوره‌ای"""
    while True:
        await asyncio.sleep(REAPER_INTERVAL)
        now = time.monotonic()
        to_delete = []

        async with XHTTP_LOCK:
            for session_id, sess in xhttp_sessions.items():
                if now - sess.last_active > SESSION_IDLE_TIMEOUT or sess.closed:
                    to_delete.append(session_id)

            for session_id in to_delete:
                sess = xhttp_sessions.pop(session_id, None)
                if sess:
                    await sess.close()


@router.on_event("startup")
async def startup_event():
    asyncio.create_task(_session_reaper())


# ── هندلرهای اصلی API ─────────────────────────────────────────────────────────

@router.post("/xhttp/packet-up")
async def xhttp_packet_up(request: Request):
    """مد مدیریت آپلینک به‌صورت Packet-based"""
    session_id = request.headers.get("x-session-id")
    link_name = request.headers.get("x-link-name", "default")
    client_ip = request.client.host if request.client else "0.0.0.0"

    if not is_ip_allowed(client_ip) or not is_link_allowed(link_name):
        raise HTTPException(status_code=403, detail="Access denied")

    body = await request.body()
    if not body:
        return {"status": "ok"}

    async with XHTTP_LOCK:
        sess = xhttp_sessions.get(session_id)

    if not sess or sess.closed:
        raise HTTPException(status_code=404, detail="Session not found")

    sess.touch()
    await sess.quota_gate.consume(len(body))

    if sess.writer and not sess.writer.is_closing():
        sess.writer.write(body)
        await sess.writer.drain()

    return {"status": "ok"}


@router.post("/xhttp/stream-up")
async def xhttp_stream_up(request: Request):
    """مد stream-up با موتور تطبیقی و اتصال مستقیم به سوکت تارگت VLESS"""
    session_id = request.headers.get("x-session-id") or secrets.token_hex(16)
    link_name = request.headers.get("x-link-name", "default")
    client_ip = request.client.host if request.client else "0.0.0.0"

    if not is_ip_allowed(client_ip) or not is_link_allowed(link_name):
        raise HTTPException(status_code=403, detail="Access denied")

    sess = XHTTPSession(session_id, link_name, client_ip)
    async with XHTTP_LOCK:
        xhttp_sessions[session_id] = sess

    # خواندن چانک اول برای پارس کردن هدر VLESS
    first_chunk = await request.stream().__anext__()
    if not first_chunk:
        raise HTTPException(status_code=400, detail="Empty stream")

    target_host, target_port, header_len = parse_vless_header(first_chunk)
    
    # برقراری اتصال به سرور مقصد
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target_host, target_port),
            timeout=TCP_CONNECT_TIMEOUT
        )
    except Exception as e:
        await sess.close()
        raise HTTPException(status_code=502, detail=f"Connection failed: {str(e)}")

    _tune_socket(writer)
    sess.reader = reader
    sess.writer = writer

    # ارسال باقی‌مانده چانک اول بعد از هدر VLESS به تارگت
    vless_payload = first_chunk[header_len:]
    if vless_payload:
        await sess.quota_gate.consume(len(vless_payload))
        writer.write(vless_payload)
        await writer.drain()

    # کوروتین خواندن متوالی از استریم آپلینک کلاینت
    async def _upload_loop():
        try:
            async for chunk in request.stream():
                if sess.closed:
                    break
                sess.touch()
                await sess.quota_gate.consume(len(chunk))
                writer.write(chunk)
                await writer.drain()
        except Exception:
            pass
        finally:
            await sess.close()

    # کوروتین خواندن از تارگت و فرستادن به صف دانلود (Downlink)
    async def _download_loop():
        try:
            bytes_in_queue = 0
            while not sess.closed:
                data = await reader.read(XHTTP_BUF)
                if not data:
                    break
                
                sess.touch()
                t0 = time.monotonic()
                
                await sess.downlink_queue.put(data)
                bytes_in_queue += len(data)

                # اِعمال کنترل جریان تطبیقی AIMD
                await sess.flow_control.wait_if_full(bytes_in_queue)
                
                drain_ms = (time.monotonic() - t0) * 1000
                sess.flow_control.adjust(drain_ms)
                bytes_in_queue = sess.downlink_queue.qsize() * XHTTP_BUF
        except Exception:
            pass
        finally:
            await sess.close()

    asyncio.create_task(_upload_loop())
    asyncio.create_task(_download_loop())

    # پاسخ Downlink به‌صورت Streaming
    async def _stream_downloader():
        fp = request.headers.get("x-fingerprint", DEFAULT_FINGERPRINT)
        while not sess.closed or not sess.downlink_queue.empty():
            try:
                data = await asyncio.wait_for(sess.downlink_queue.get(), timeout=1.0)
                yield data
            except asyncio.TimeoutError:
                continue

    headers = _resp_headers(request.headers.get("x-fingerprint", DEFAULT_FINGERPRINT))
    headers["x-session-id"] = session_id

    return StreamingResponse(_stream_downloader(), headers=headers)
