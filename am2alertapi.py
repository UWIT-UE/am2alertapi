#!/usr/bin/env python3
#
# API adapter from Prometheus Alertmanager to UW AlertAPI
#   ssh://git@git.s.uw.edu/ue/monitoring.git

# All options via environment variables
#  ALERTAPI_TOKEN - token for AlertAPI access
#  ALERTAPI_URL - URL for AlertAPI, not including path
#  ALERT_ORGANIZATION - Service Now Organization Name

from quart import Quart, Response, request, abort, jsonify
from prometheus_client import multiprocess
from prometheus_client import generate_latest, CollectorRegistry, CONTENT_TYPE_LATEST, Counter
import asyncio
import json
import httpx
import random
import os
import sys
import signal
import logging

server = Quart(__name__)

def cleanexit(signum, frame):
    server.logger.info('Shutting down')
    sys.exit()

signal.signal(signal.SIGTERM, cleanexit)
signal.signal(signal.SIGINT, cleanexit)

# this determines the Focus to AlertAPI urgency mapping
focus_2_urgency = {1: 1, 2: 1, 3: 2, 4: 3}

# Configure logging
log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
valid_levels = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL
}
log_level_value = valid_levels.get(log_level, logging.INFO)

logging.basicConfig(level=log_level_value, format='%(asctime)s %(levelname)s [%(name)s.%(process)d] %(message)s')
server.logger.setLevel(log_level_value)
server.logger.info(f"Log level set to {log_level}")

if not 'ALERTAPI_TOKEN' in os.environ:
    server.logger.error('Environment ALERTAPI_TOKEN not set')
    sys.exit(1)

if not 'ALERTAPI_URL' in os.environ:
    server.logger.error('Environment ALERTAPI_URL not set')
    sys.exit(1)

if not 'ALERT_ORGANIZATION' in os.environ:
    server.logger.error('Environment ALERT_ORGANIZATION not set')
    sys.exit(1)

ci_organization = os.environ['ALERT_ORGANIZATION']
token = os.environ['ALERTAPI_TOKEN']
api_url = os.environ['ALERTAPI_URL'].rstrip('/')
alert_endpoint = api_url + '/v1/alert'
keepalive_endpoint = api_url + '/v1/keepalive'

server.logger.info('Config url="{0}"'.format(api_url))
server.logger.info('Config alert_endpoint="{0}"'.format(alert_endpoint))
server.logger.info('Config keepalive_endpoint="{0}"'.format(keepalive_endpoint))
server.logger.info('Config token="{0}"'.format("*" * len(token)))
server.logger.info('Config org="{0}"'.format(ci_organization))

response_count = Counter('am2alertapi_responses_total', 'HTTP responses', ['api_endpoint', 'status_code'])
registry = CollectorRegistry()
multiprocess.MultiProcessCollector(registry)

def translate(amalert):
    results = []
    try:
        for alert in amalert['alerts']:
            result = {}
            result['ci'] = {}
            result['component'] = {}
            result['message'] = ''
            result['ci']['organization'] = ci_organization

            # Heirarchy of ci selection
            if alert['labels'].get('hostname'):
                result['ci']['name'] = alert['labels']['hostname']
            if alert['labels'].get('cluster'):
                result['ci']['name'] = alert['labels']['cluster']
            if alert['labels'].get('ci_name'):
                result['ci']['name'] = alert['labels']['ci_name']
            if alert['labels'].get('ci_sysid'):
                result['ci']['sysid'] = alert['labels']['ci_sysid']

            result['component']['name'] = alert['labels']['alertname']
            result['title'] = alert['annotations']['summary']
            prom_url = alert['generatorURL']
            result['message'] = '{}\n\nsource: {}'.format(
                alert['annotations']['description'], prom_url)

            if alert['labels'].get('kba'):
                result['kba'] = {'number': alert['labels']['kba']}

            if alert['status'] == 'firing':
                result['urgency'] = focus_2_urgency[int(alert['labels']['focus'])]
            else:
                result['urgency'] = 'OK'

            if alert['labels'].get('watchdog_timeout'):
                result['timeout'] = alert['labels']['watchdog_timeout']

            results.append(result)

    except LookupError as e:
        server.logger.error("Alert input missing required labels/annotations/attributes: {}".format(e))
        response_count.labels(api_endpoint='/', status_code='406').inc()
        abort(406, description="Missing required labels/annotations/attributes {}".format(e))

    return results


@server.route('/', methods=['POST'])
async def alert():
    """Submit posted alertmanager alerts to UW alertAPI"""
    headers = {
        'Authorization': 'Bearer {0}'.format(token),
        'Content-Type': 'application/json'
        }

    data = await request.get_json(force=True, silent=False, cache=True)
    alerts = translate(data)
    for alert in alerts:
        json_alert = json.dumps(alert)
        await asyncio.sleep(random.uniform(1,10000)/1000)
        try:
            async with httpx.AsyncClient() as api_client:
                api_response = await api_client.post(alert_endpoint, headers=headers, data=json_alert, timeout=30)
        except httpx.TimeoutException:
            server.logger.error('Timeout with alertAPI')
            response_count.labels(api_endpoint='/', status_code='500').inc()
            abort(500, description="timeout with alertapi")
        except httpx.ConnectError:
            server.logger.error('Unable to connect with alertAPI')
            response_count.labels(api_endpoint='/', status_code='500').inc()
            abort(500, description="connect error with alertapi")
        else:
            server.logger.info('Alert {}:{} urgency {} return_code {}'.format(alert['ci']['name'],
                alert['component']['name'], alert['urgency'], api_response.status_code))

    response_count.labels(api_endpoint='/', status_code=str(api_response.status_code)).inc()
    return Response(status=api_response.status_code)


@server.route('/watchdog', methods=['POST'])
async def watchdog():
    """A watchdog using UW alertAPI keepalive.

    Watchdog expects a firing alert at a regular interval
    and will call alertAPI when the firing alert is missing.
    Contact must be made before the value of the label
    watchdog_timeout, which defaults to 5 minutes.
    """
    headers = {
        'Authorization': 'Bearer {0}'.format(token),
        'Content-Type': 'application/json'
        }

    data = await request.get_json(force=True, silent=False, cache=True)
    alerts = translate(data)
    for alert in alerts:
        if not alert.get('timeout'):
            alert['timeout'] = 5
        json_alert = json.dumps(alert)
        try:
            async with httpx.AsyncClient() as api_client:
                api_response = await api_client.post(keepalive_endpoint, headers=headers, data=json_alert, timeout=30)
        except httpx.TimeoutException:
            server.logger.error('Timeout with alertAPI keepalive')
            response_count.labels(api_endpoint='/watchdog', status_code='500').inc()
            abort(500, description="timeout with alertapi keepalive")
        except httpx.ConnectError:
            server.logger.error('Connect error with alertAPI keepalive')
            response_count.labels(api_endpoint='/watchdog', status_code='500').inc()
            abort(500, description="connect error with alertapi keepalive")
        else:
            server.logger.info('Keepalive {}:{} urgency {} timeout {} return_code {}'.format(alert['ci']['name'],
                alert['component']['name'], alert['urgency'], alert['timeout'], api_response.status_code))

    response_count.labels(api_endpoint='/watchdog', status_code=str(api_response.status_code)).inc()
    return Response(status=api_response.status_code)


@server.route('/healthz')
async def healthz():
    """Return a 200 illustrating responsiveness."""
    response_count.labels(api_endpoint='/healthz', status_code='200').inc()
    return Response(status=200)

@server.route('/metrics')
async def metrics():
    """Return Prometheus metrics."""
    response_count.labels(api_endpoint='/metrics', status_code='200').inc()
    return Response(generate_latest(registry), mimetype=CONTENT_TYPE_LATEST)

