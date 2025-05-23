import multiprocessing
from os import environ as env

# Port to bind to
bind = f":{int(env.get('PORT', 5000))}"

# Number of processes to launch
workers = int(env.get('WORKERS', multiprocessing.cpu_count()))

# Number of concurrent handled connections
threads = int(env.get('THREADS', 4))
worker_connections = int(env.get('WORKER_CONNECTIONS', '1000'))

# Recycle the process after X request randomized by the jitter
max_requests = int(env.get('MAX_REQUESTS', '1000'))
max_requests_jitter = int(env.get('MAX_REQUESTS_JITTER', '100'))

# Connection timeouts
graceful_timeout = int(env.get('GRACEFUL_TIMEOUT', '30'))
timeout = int(env.get('TIMEOUT', '30'))

# TLS/SSL Configuration
certfile = env.get('CERTFILE')
keyfile = env.get('KEYFILE')

# Request header max size configuration
#  NOTE: This allows to pass JWT tokens bigger then 8k to AL through the headers
limit_request_field_size = int(env.get("LIMIT_REQUEST_FIELD_SIZE", "8190"))

# Request line max size configuration
limit_request_line = int(env.get("LIMIT_REQUEST_LINE", "4094"))
