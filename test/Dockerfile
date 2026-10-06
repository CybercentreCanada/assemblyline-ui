ARG PYTHON_VERSION=3.14
FROM python:${PYTHON_VERSION}-slim-trixie

# Create Assemblyline source directory
RUN mkdir -p /etc/assemblyline \
    /var/cache/assemblyline \
    /var/lib/assemblyline/{flowjs,bundling} \
    /var/log/assemblyline \
    /opt/alv4

WORKDIR /opt/alv4

# Setup environment varibles
ENV PYTHONPATH /opt/alv4/assemblyline-base:/opt/alv4/assemblyline-core:/opt/alv4/assemblyline-ui

COPY ./assemblyline-base assemblyline-base
COPY ./assemblyline-base/docker/compile_pkglist.txt compile_pkglist.txt
COPY ./assemblyline-base/docker/required_pkglist.txt required_pkglist.txt
COPY ./assemblyline-core assemblyline-core
COPY ./assemblyline-ui assemblyline-ui

# Install Assemblyline packages in editable mode
RUN apt-get update -yy && apt-get -yy upgrade \
    # Install system packages to compile some Python dependencies
    && apt-get install --no-install-recommends -y $(grep -vE "^\s*(#|$)" compile_pkglist.txt | tr "\n" " ") \
    # Install required packages that are needed at runtime and compile time
    && apt-get install --no-install-recommends -y zip $(grep -vE "^\s*(#|$)" required_pkglist.txt | tr "\n" " ") \
    # Update pip to the latest version
    && pip install --upgrade pip \
    # Install Assemblyline packages in editable mode
    && pip install ./assemblyline-base[test] \
    && pip install ./assemblyline-core[test] \
    && pip install ./assemblyline-ui[test,socketio] \
    # Remove system packages used for building Python dependencies
    && apt-get purge -y $(grep -vE "^\s*(#|$)" compile_pkglist.txt | tr "\n" " ") && apt-get autoremove -y \
    # Remove pip cache and apt lists
    && rm -rf /root/.cache/pip \
    && rm -rf /var/lib/apt/lists/*
