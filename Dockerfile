FROM python:3.10-slim

ENV PROMETHEUS_MULTIPROC_DIR=/tmp/metric-multi
RUN mkdir -p /tmp/metric-multi

ENV PATH="/venv/bin:$PATH"
RUN python3 -m venv /venv

COPY requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt
COPY gunicorn.conf.py /app/gunicorn.conf.py
COPY am2alertapi.py /app/am2alertapi.py

ENTRYPOINT ["gunicorn", "app.am2alertapi:server", "-b", ":3080", "-c", "/app/gunicorn.conf.py", \
            "--worker-class=eventlet", "--workers=3", "--log-level", "INFO"]

# With Apache style request logging
#ENTRYPOINT ["gunicorn", "app.am2alertapi:server", "-b", ":3080" \
#            "--worker-class=eventlet", "--access-logfile", "-", "--log-level", "INFO"]

