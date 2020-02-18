FROM cccs/assemblyline:latest

ARG version

# Switch to root to install dependancies
USER root

RUN apt install libldap2-dev libsasl2-dev

# Install assemblyline UI
RUN pip3 install assemblyline-ui==$version

# Switch back to assemblyline and run the app
USER assemblyline
CMD ["gunicorn", "assemblyline_ui.app:app", "--config=/usr/local/lib/python3.7/site-packages/assemblyline_ui/gunicorn_config.py"]
