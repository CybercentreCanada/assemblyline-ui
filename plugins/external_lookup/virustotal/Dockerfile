FROM python:3.9-slim-buster AS base
# Upgrade packages
RUN apt-get update && apt-get -yy upgrade && rm -rf /var/lib/apt/lists/*

# Patch Python 3.9 for FIPS - https://github.com/python/cpython/issues/95231 (Not necessary for Python 3.10+)
RUN sed -i -e 's/if e.errno == errno.EINVAL:/if e.errno in {errno.EINVAL, errno.EPERM, errno.ENOSYS}:/g' /usr/local/lib/python3.9/crypt.py

# Get required apt packages
RUN apt-get update && apt-get install -yy libffi6 && rm -rf /var/lib/apt/lists/*

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
