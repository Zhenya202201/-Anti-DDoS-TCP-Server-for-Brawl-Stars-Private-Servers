🚀 Как запустить

🔧 Требования

Python 3.10+

Redis-сервер (локально или в докере)

Зависимости из requirements.txt:


aioredis
pyfiglet

Установка зависимостей:

pip install -r requirements.txt

🧱 Запуск Redis

# Локально
redis-server

# Или в Docker
docker run -d -p 6379:6379 redis

▶️ Запуск сервера

python antiddos_server.py
