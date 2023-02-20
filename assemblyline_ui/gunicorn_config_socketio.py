from os import environ as env

# TLS/SSL Configuration
certfile = env.get('CERTFILE')
keyfile = env.get('KEYFILE')
