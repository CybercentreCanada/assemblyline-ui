from os import environ as env
import multiprocessing

PORT = int(env.get("PORT", 5000))

# Gunicorn config
bind = f":{PORT}"
workers = multiprocessing.cpu_count() * 2 + 1
threads = 2 * multiprocessing.cpu_count()