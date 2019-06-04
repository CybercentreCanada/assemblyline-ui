FROM cccs/assemblyline:latest

ARG version

# Switch to root to install dependancies
USER root

# Install assemblyline UI
RUN pip3 install assemblyline-ui==$version

# Switch back to assemblyline and run the app
USER assemblyline
CMD ["gunicorn", "-b", ":5002", "-w", "1", "-k", "gevent", "al_ui.socketsrv:app"]
