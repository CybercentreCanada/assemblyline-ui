ARG branch=latest
ARG base=cccs/assemblyline
FROM $base:$branch AS base
# Switch to root to install common dependancies
USER root
RUN apt-get update && apt-get install -yy libldap-2.5-0 libsasl2-2 zip 7zip && rm -rf /var/lib/apt/lists/*

# Create a temporarary image to compile dependencies
FROM base AS builder
ARG version

# Switch to root to install dependancies
USER root
RUN apt-get update && apt-get install -yy build-essential libldap2-dev libsasl2-dev && rm -rf /var/lib/apt/lists/*

# Install assemblyline UI into local so it merges new and old packages
USER assemblyline
RUN touch /tmp/before-pip
COPY setup.py dist* dist/
RUN pip install --no-cache-dir -f dist --user assemblyline-core==$version assemblyline-ui==$version

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

# Make sure base required UI directory are present
RUN mkdir -p /var/lib/assemblyline/bundling
RUN mkdir -p /var/lib/assemblyline/flowjs
RUN mkdir -p /var/lib/assemblyline/submit

# Run the API server
CMD ["gunicorn", "assemblyline_ui.patched:app", "--config=python:assemblyline_ui.gunicorn_config", "--worker-class", "gevent"]
