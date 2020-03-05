FROM cccs/assemblyline:latest AS base
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
RUN pip3 install --user assemblyline-ui==$version
RUN chown root:root -R /var/lib/assemblyline/.local

# Create a new image, without compile depedencies
FROM base

# Get the updated local dir from builder
COPY --chown=assemblyline:assemblyline --from=builder /var/lib/assemblyline/.local /var/lib/assemblyline/.local

# Switch back to assemblyline and run the app
USER assemblyline
CMD ["gunicorn", "assemblyline_ui.app:app", "--config=~/.local/lib/python3.7/site-packages/assemblyline_ui/gunicorn_config.py"]
