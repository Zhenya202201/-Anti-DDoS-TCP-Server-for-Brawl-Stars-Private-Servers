import asyncio
import time
import random
import string
from collections import defaultdict

# Настройки
HOST = '0.0.0.0'
PORT = 9999
MAX_CONNECTIONS_PER_IP = 5
GLOBAL_CONNECTIONS_PER_SEC = 100
TIME_WINDOW = 10  # секунд
BAN_DURATION = 120  # секунд

# Хранилища
ip_log = defaultdict(list)
fingerprint_log = defaultdict(int)
banned_ips = {}
banned_fingerprints = set()
global_connection_times = []

lock = asyncio.Lock()

def generate_challenge():
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))

def extract_fingerprint(data):
    try:
        parts = data.strip().split(':')
        if len(parts) != 2:
            return None
        account_id = parts[0]
        return f"{account_id.lower()}_{len(data)}"
    except:
        return None

def is_banned(ip):
    if ip in banned_ips:
        if time.time() - banned_ips[ip] > BAN_DURATION:
            del banned_ips[ip]
            return False
        return True
    return False

def is_ip_rate_limited(ip):
    now = time.time()
    ip_log[ip] = [t for t in ip_log[ip] if now - t < TIME_WINDOW]
    if len(ip_log[ip]) >= MAX_CONNECTIONS_PER_IP:
        return True
    ip_log[ip].append(now)
    return False

def is_global_rate_limited():
    now = time.time()
    global_connection_times[:] = [t for t in global_connection_times if now - t < 1]
    if len(global_connection_times) >= GLOBAL_CONNECTIONS_PER_SEC:
        return True
    global_connection_times.append(now)
    return False

async def slow_read(reader, max_bytes=64, delay=0.01):
    """Медленное чтение из сокета — полезно против спамеров"""
    data = b''
    try:
        while len(data) < max_bytes:
            chunk = await asyncio.wait_for(reader.read(1), timeout=5)
            if not chunk or chunk == b'\n':
                break
            data += chunk
            await asyncio.sleep(delay)  # задержка
        return data.decode(errors='ignore').strip()
    except:
        return ""

async def handle_client(reader, writer):
    addr = writer.get_extra_info("peername")
    ip = addr[0]

    async with lock:
        if is_banned(ip):
            print(f"[!] Блок: {ip}")
            writer.close()
            await writer.wait_closed()
            return

        if is_global_rate_limited():
            print(f"[!] Глобальный лимит соединений")
            writer.close()
            await writer.wait_closed()
            return

        if is_ip_rate_limited(ip):
            print(f"[!] Частые подключения от IP {ip} — бан")
            banned_ips[ip] = time.time()
            writer.close()
            await writer.wait_closed()
            return

    try:
        # === Challenge ===
        challenge = generate_challenge()
        writer.write(f"Challenge: {challenge}\n".encode())
        await writer.drain()

        response = await slow_read(reader)
        if response != challenge:
            writer.write(b"Invalid challenge.\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            print(f"[!] Неверный challenge от {ip}")
            return

        # === Запрос аккаунта ===
        writer.write(b"Send your account_id:data\n")
        await writer.drain()
        raw_data = await slow_read(reader, max_bytes=128)

        fingerprint = extract_fingerprint(raw_data)
        if not fingerprint:
            writer.close()
            await writer.wait_closed()
            return

        if fingerprint in banned_fingerprints:
            print(f"[!] Забанен fingerprint {fingerprint}")
            writer.close()
            await writer.wait_closed()
            return

        fingerprint_log[fingerprint] += 1
        if fingerprint_log[fingerprint] > 5:
            banned_fingerprints.add(fingerprint)
            print(f"[!] Fingerprint {fingerprint} забанен за спам")
            writer.close()
            await writer.wait_closed()
            return

        parts = raw_data.strip().split(':')
        account_id = parts[0]
        if len(account_id) < 4 or not account_id.isalnum():
            writer.write(b"Invalid account ID.\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            print(f"[!] Подозрительный аккаунт от {ip}")
            return

        print(f"[+] Подключение: {ip}, аккаунт: {account_id}")
        writer.write(b"Connected successfully.\n")
        await writer.drain()

    except Exception as e:
        print(f"[!] Ошибка с {ip}: {e}")
    finally:
        writer.close()
        await writer.wait_closed()

async def main():
    server = await asyncio.start_server(
        handle_client,
        HOST,
        PORT,
        backlog=5000  # Увеличенная очередь входящих соединений
    )

    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    print(f"[i] Сервер слушает на {addrs}")

    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Сервер остановлен.")