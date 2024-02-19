FROM python:3.11-slim-bookworm AS base
# Upgrade packages
RUN apt-get update && apt-get -yy upgrade && rm -rf /var/lib/apt/lists/*

# Get required apt packages
RUN apt-get update && apt-get install -yy libffi8 && rm -rf /var/lib/apt/lists/*

# Make sure root account is locked so 'su' commands fail all the time
RUN passwd -l root


FROM base as builder
# support mirrors
ENV PIP_DISABLE_PIP_VERSION_CHECK=yes
ARG PIP_CERT
ARG PIP_CLIENT_CERT
ARG PIP_TRUSTED_HOST
ARG PIP_INDEX_URL
ARG PIP_EXTRA_INDEX_URL

RUN mkdir /install
WORKDIR /install

# Get required apt packages
RUN apt-get update \
    && apt-get install -yy build-essential libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install --prefix=/install -r /tmp/requirements.txt


FROM base as release
# create local user
ARG UID=1000
RUN useradd --create-home --shell /bin/bash -u $UID assemblyline

# install app
USER assemblyline
WORKDIR /home/assemblyline
COPY --from=builder /install /usr/local
ENV APP_MODULE=app:app
COPY --chown=assemblyline:assemblyline app.py gunicorn_config.py ./

# run app
ENV GUNICORN_CONF=/home/assemblyline/gunicorn_config.py
ENV WORKER_CLASS=gevent
ENV HOST=0.0.0.0
ENV PORT=8000
EXPOSE $PORT
ENTRYPOINT gunicorn -c "$GUNICORN_CONF" -k "$WORKER_CLASS" --pythonpath /home/assemblyline "$APP_MODULE"
