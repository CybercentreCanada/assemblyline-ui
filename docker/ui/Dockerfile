ARG branch=latest
FROM cccs/assemblyline:$branch AS base
# Switch to root to install common dependancies
USER root
RUN apt-get update && apt-get install -yy libldap-2.4-2 libsasl2-2 && rm -rf /var/lib/apt/lists/*

# Create a temporarary image to compile dependencies
FROM base AS builder
ARG version

# Switch to root to install dependancies
USER root
RUN apt-get update && apt-get install -yy build-essential libldap2-dev libsasl2-dev && rm -rf /var/lib/apt/lists/*

# Install assemblyline UI into local so it merges new and old packages
USER assemblyline
RUN touch /tmp/before-pip
RUN pip install --no-cache-dir --user assemblyline-ui==$version

# Remove files that existed before the pip install so that our copy command below doesn't take a snapshot of
# files that already exist in the base image
RUN find /var/lib/assemblyline/.local -type f ! -newer /tmp/before-pip -delete

# Switch back to root and change the ownership of the files to be copied due to bitbucket pipeline uid nonsense
USER root
RUN chown root:root -R /var/lib/assemblyline/.local

# Create a new image, without compile depedencies
FROM base

# Get the updated local dir from builder
COPY --chown=assemblyline:assemblyline --from=builder /var/lib/assemblyline/.local /var/lib/assemblyline/.local

# Switch back to assemblyline and run the app
USER assemblyline

ENV UWSGI_MAX_REQUESTS=${MAX_REQUESTS:-1000}
ENV UWSGI_MAX_REQUESTS_DELTA=${MAX_REQUESTS_JITTER:-100}
ENV UWSGI_WORKERS=${WORKERS:-2}
ENV UWSGI_THREADS=${THREADS:-25}
ENV UWSGI_PROTOCOL=${PROTOCOL:-http}
ENV UWSGI_SOCKET=0.0.0.0:${PORT:-5000}

CMD ["uwsgi", "--master", "--disable-logging", "--enable-threads", "--die-on-term", "--module", "assemblyline_ui.app:app"]
