from os import environ as env
import multiprocessing

# Gunicorn config
bind = f":{int(env.get('PORT', 5000))}"
workers = int(env.get('WORKERS', multiprocessing.cpu_count()))
threads = int(env.get('THREADS', 4))
max_requests = int(env.get('MAX_REQUESTS', '1000'))
