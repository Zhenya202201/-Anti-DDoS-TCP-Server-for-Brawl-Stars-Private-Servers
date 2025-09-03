import asyncio
import time
import random
import string
import re
import hashlib
import json
import os
from datetime import datetime

import aioredis
import pyfiglet

# Настройки
HOST = '0.0.0.0'
PORT = 9999
MAX_CONN_PER_IP = 5
GLOBAL_CONN_PER_SEC = 100
TIME_WINDOW = 10
BAN_DURATION = 120
MAX_FP_HITS = 5
MAX_UNIQUE_FP_PER_IP = 20
CLIENT_TIMEOUT = 10
SESSION_TTL = 300
POW_DIFFICULTY = 3
BAN_LOG_PATH = "ban.json"

# Хранилища
ip_log = {}
global_conn_times = []
log_queue = asyncio.Queue()
account_id_re = re.compile(r"^[a-zA-Z0-9_]{4,20}$")

# ========== Banner ==========
def print_banner():
    print(f"\033[92m{pyfiglet.figlet_format('AntiDDoS-Server')}\033[0m")

# ========== Ban Logging ==========
def load_ban_stats():
    if os.path.exists(BAN_LOG_PATH):
        with open(BAN_LOG_PATH, "r") as f:
            return json.load(f)
    return {"ips": {}, "fingerprints": {}}

def save_ban_stats(stats):
    with open(BAN_LOG_PATH, "w") as f:
        json.dump(stats, f, indent=4)

def update_ban_stat_ip(ip):
    stats = load_ban_stats()
    entry = stats["ips"].get(ip, {"count": 0})
    entry["count"] += 1
    entry["last_ban"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    stats["ips"][ip] = entry
    save_ban_stats(stats)

def update_ban_stat_fp(fp):
    stats = load_ban_stats()
    entry = stats["fingerprints"].get(fp, {"count": 0})
    entry["count"] += 1
    entry["last_ban"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    stats["fingerprints"][fp] = entry
    save_ban_stats(stats)

# ========== Вспомогательные ==========
def extract_fp(data: str, ip: str) -> str | None:
    parts = data.strip().split(':')
    if len(parts) != 2:
        return None
    return hashlib.sha256(f"{ip}:{parts[0].lower()}".encode()).hexdigest()

def gen_pow():
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

def valid_pow(challenge: str, sol: str) -> bool:
    return hashlib.sha256((challenge + sol).encode()).hexdigest().startswith('0' * POW_DIFFICULTY)

async def slow_read(reader, max_bytes=64, delay=0.01):
    data = b''
    try:
        while len(data) < max_bytes:
            chunk = await asyncio.wait_for(reader.read(1), timeout=5)
            if not chunk:
                break
            data += chunk
            await asyncio.sleep(delay)
        return data.decode(errors='ignore').strip()
    except:
        return ""

async def log_writer():
    while True:
        print(await log_queue.get())

def rate_limit_ip(ip: str) -> bool:
    now = time.time()
    times = [t for t in ip_log.get(ip, []) if now - t < TIME_WINDOW]
    times.append(now)
    ip_log[ip] = times
    return len(times) > MAX_CONN_PER_IP

def global_rate_limit() -> bool:
    now = time.time()
    global_conn_times[:] = [t for t in global_conn_times if now - t < 1]
    global_conn_times.append(now)
    return len(global_conn_times) > GLOBAL_CONN_PER_SEC

# ========== Основной хендлер ==========
async def handle_client(reader, writer, redis):
    ip = writer.get_extra_info("peername")[0]
    async def core():
        if await redis.exists(f"ban:ip:{ip}"):
            update_ban_stat_ip(ip)
            await log_queue.put(f"[BAN] IP: {ip}")
            return

        if global_rate_limit() or rate_limit_ip(ip):
            await redis.setex(f"ban:ip:{ip}", BAN_DURATION, "1")
            update_ban_stat_ip(ip)
            await log_queue.put(f"[BAN-LIMIT] IP: {ip}")
            return

        challenge = gen_pow()
        writer.write(f"PoW: sha256({challenge}+X) → hash starts with {'0'*POW_DIFFICULTY}\n".encode())
        await writer.drain()

        sol = await asyncio.wait_for(reader.readline(), timeout=CLIENT_TIMEOUT)
        if not valid_pow(challenge, sol.decode().strip()):
            update_ban_stat_ip(ip)
            return

        token = hashlib.sha256(str(random.random()).encode()).hexdigest()
        await redis.setex(f"session:{token}", SESSION_TTL, ip)
        writer.write(f"TOKEN:{token}\n".encode())
        await writer.drain()

        response = await asyncio.wait_for(reader.readline(), timeout=CLIENT_TIMEOUT)
        if response.decode().strip() != token:
            await redis.setex(f"ban:ip:{ip}", BAN_DURATION, "1")
            update_ban_stat_ip(ip)
            await log_queue.put(f"[BAN-TOKEN] IP: {ip}")
            return

        writer.write(b"Send account_id:data\n")
        await writer.drain()

        raw = await asyncio.wait_for(reader.readline(), timeout=CLIENT_TIMEOUT)
        fp = extract_fp(raw.decode(), ip)
        if not fp:
            return

        if await redis.exists(f"ban:fp:{fp}"):
            update_ban_stat_fp(fp)
            await log_queue.put(f"[BAN-FP] {fp}")
            return

        hits = int(await redis.get(f"count:fp:{fp}") or 0)
        if hits >= MAX_FP_HITS:
            await redis.setex(f"ban:fp:{fp}", BAN_DURATION, "1")
            update_ban_stat_fp(fp)
            await log_queue.put(f"[BAN-FP-SPAM] {fp}")
            return
        await redis.incr(f"count:fp:{fp}")
        await redis.expire(f"count:fp:{fp}", TIME_WINDOW)

        uniq = int(await redis.get(f"fp_unique:{ip}") or 0)
        if uniq >= MAX_UNIQUE_FP_PER_IP:
            await redis.setex(f"ban:ip:{ip}", BAN_DURATION, "1")
            update_ban_stat_ip(ip)
            await log_queue.put(f"[BAN-MANY-FP] IP: {ip}")
            return
        await redis.incr(f"fp_unique:{ip}")
        await redis.expire(f"fp_unique:{ip}", TIME_WINDOW)

        account_id = raw.decode().split(':',1)[0]
        if not account_id_re.match(account_id):
            await log_queue.put(f"[BAD-ID] {ip} -> {raw.decode().strip()}")
            return

        await log_queue.put(f"[OK] Connected: IP {ip}, account {account_id}")
        writer.write(b"Connected successfully.\n")
        await writer.drain()

    try:
        await asyncio.wait_for(core(), timeout=CLIENT_TIMEOUT * 2)
    except asyncio.TimeoutError:
        await redis.setex(f"ban:ip:{ip}", BAN_DURATION, "1")
        update_ban_stat_ip(ip)
        await log_queue.put(f"[TIMEOUT] IP: {ip}")
    finally:
        writer.close()
        await writer.wait_closed()

# ========== Main ==========
async def main():
    redis = await aioredis.from_url("redis://localhost", encoding="utf-8", decode_responses=True)
    server = await asyncio.start_server(lambda r, w: handle_client(r, w, redis), HOST, PORT, backlog=5000)
    asyncio.create_task(log_writer())

    await log_queue.put(f"[INFO] Listening on {HOST}:{PORT}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        print_banner()
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[Stopped]")