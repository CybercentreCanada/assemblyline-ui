FROM python:3.7-stretch

ARG version

RUN apt-get update
RUN apt-get install -yy build-essential libffi-dev libfuzzy-dev

RUN pip3 install "urllib3<1.25,>=1.21.1"
RUN pip3 install assemblyline-ui==$version

RUN mkdir -p /etc/assemblyline
RUN mkdir -p /var/cache/assemblyline
RUN mkdir -p /var/log/assemblyline

CMD ["gunicorn", "al_ui.app:app", "--config=/usr/local/lib/python3.7/site-packages/al_ui/gunicorn_config.py"]
