FROM cccs/assemblyline:latest

ARG version

# Switch to root to install dependancies
USER root

RUN apt install libldap2-dev libsasl2-dev

# Install assemblyline UI
RUN pip3 install assemblyline-ui==$version

# clear pip cache
RUN rm -rf ~/.cache/pip

# Switch back to assemblyline and run the app
USER assemblyline
CMD ["gunicorn", "-b", ":5002", "-w", "1", "-k", "geventwebsocket.gunicorn.workers.GeventWebSocketWorker", "assemblyline_ui.socketsrv:app"]
