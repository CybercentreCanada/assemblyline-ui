from os import environ as env
import multiprocessing

# Gunicorn config
bind = f":{int(env.get('PORT', 5000))}"
workers = int(env.get('WORKERS', multiprocessing.cpu_count() * 2 + 1))
threads = int(env.get('THREADS', 2 * multiprocessing.cpu_count()))
