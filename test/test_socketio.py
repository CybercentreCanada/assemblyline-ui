import pytest
import requests
import socketio
import time


from assemblyline.common import forge
from assemblyline.common.uid import get_random_id
from assemblyline.odm.messages.alert import AlertMessage
from assemblyline.odm.messages.alerter_heartbeat import AlerterMessage
from assemblyline.odm.messages.dispatcher_heartbeat import DispatcherMessage
from assemblyline.odm.messages.expiry_heartbeat import ExpiryMessage
from assemblyline.odm.messages.ingest_heartbeat import IngestMessage
from assemblyline.odm.messages.service_heartbeat import ServiceMessage
from assemblyline.odm.messages.service_timing_heartbeat import ServiceTimingMessage
from assemblyline.odm.messages.submission import SubmissionMessage
from assemblyline.odm.randomizer import random_model_obj
from assemblyline.remote.datatypes.queues.comms import CommsQueue

# noinspection PyUnresolvedReferences
from base import get_api_data, create_users, wipe_users

from assemblyline.remote.datatypes.queues.named import NamedQueue

config = forge.get_config()
ds = forge.get_datastore()


def purge_socket():
    wipe_users(ds)

@pytest.fixture(scope='function')
def login_session():
    session = requests.Session()
    data = get_api_data(session, f"http://localhost:5000/api/v4/auth/login/",
                        params={'user': 'admin', 'password': 'admin'})
    return data, session

@pytest.fixture(scope="module")
def datastore(request):
    create_users(ds)
    request.addfinalizer(purge_socket)
    return ds

@pytest.fixture(scope="function")
def sio(login_session):
    _, session = login_session
    sio = socketio.Client()
    headers = {
        'Cookie': f"session={session.cookies.get('session', None)}",
        'X-XSRF-TOKEN': session.headers.get('X-XSRF-TOKEN', None),
    }

    sio.connect('http://localhost:5002',
                namespaces=['/alerts', '/live_submission', "/submissions", '/status'],
                headers=headers)

    return sio


# noinspection PyUnusedLocal
def test_alert_namespace(datastore, sio):
    alert_queue = CommsQueue('alerts', private=True)
    test_id = get_random_id()

    created = random_model_obj(AlertMessage)
    created.msg_type = "AlertCreated"

    updated = random_model_obj(AlertMessage)
    updated.msg_type = "AlertUpdated"

    test_res_array = []

    @sio.on('monitoring', namespace='/alerts')
    def on_monitoring(data):
        # Confirmation that we are waiting for alerts
        test_res_array.append(('on_monitoring', data == test_id))

    @sio.on('AlertCreated', namespace='/alerts')
    def on_alert_created(data):
        test_res_array.append(('on_alert_created', data == created.as_primitives()['msg']))

    @sio.on('AlertUpdated', namespace='/alerts')
    def on_alert_updated(data):
        test_res_array.append(('on_alert_updated', data == updated.as_primitives()['msg']))

    try:
        sio.emit('alert', test_id, namespace='/alerts')
        sio.sleep(1)

        alert_queue.publish(created.as_primitives())
        alert_queue.publish(updated.as_primitives())

        start_time = time.time()

        while len(test_res_array) < 3 or time.time() - start_time < 5:
            sio.sleep(0.1)

        assert len(test_res_array) == 3

        for test, result in test_res_array:
            if not result:
                pytest.fail(f"{test} failed.")

    finally:
        sio.disconnect()


# noinspection PyUnusedLocal
def test_live_namespace(datastore, sio):
    wq_data = {'wq_id': get_random_id()}
    wq = NamedQueue(wq_data['wq_id'], private=True)

    start_msg = {'status_code': 200, 'msg': "Start listening..."}
    stop_msg = {'status_code': 200, 'msg': "All messages received, closing queue..."}
    cachekey_msg = {'status_code': 200, 'msg': get_random_id()}
    cachekeyerr_msg = {'status_code': 200, 'msg': get_random_id()}

    test_res_array = []

    @sio.on('start', namespace='/live_submission')
    def on_start(data):
        test_res_array.append(('on_start', data == start_msg))

    @sio.on('stop', namespace='/live_submission')
    def on_stop(data):
        test_res_array.append(('on_stop', data == stop_msg))

    @sio.on('cachekey', namespace='/live_submission')
    def on_cachekey(data):
        test_res_array.append(('on_cachekey', data == cachekey_msg))

    @sio.on('cachekeyerr', namespace='/live_submission')
    def on_stop(data):
        test_res_array.append(('on_cachekeyerr', data == cachekeyerr_msg))

    try:
        sio.emit('listen', wq_data, namespace='/live_submission')
        sio.sleep(1)

        wq.push({"status": "START"})
        wq.push({"status": "OK", "cache_key": cachekey_msg['msg']})
        wq.push({"status": "FAIL", "cache_key": cachekeyerr_msg['msg']})
        wq.push({"status": "STOP"})

        start_time = time.time()

        while len(test_res_array) < 4 and time.time() - start_time < 5:
            sio.sleep(0.1)

        assert len(test_res_array) == 4

        for test, result in test_res_array:
            if not result:
                pytest.fail(f"{test} failed.")

    finally:
        sio.disconnect()


# noinspection PyUnusedLocal
def test_status(datastore, sio):
    status_queue = CommsQueue('status', private=True)
    monitoring = get_random_id()

    alerter_hb_msg = random_model_obj(AlerterMessage).as_primitives()
    dispatcher_hb_msg = random_model_obj(DispatcherMessage).as_primitives()
    expiry_hb_msg = random_model_obj(ExpiryMessage).as_primitives()
    ingest_hb_msg = random_model_obj(IngestMessage).as_primitives()
    service_hb_msg = random_model_obj(ServiceMessage).as_primitives()
    service_timing_msg = random_model_obj(ServiceTimingMessage).as_primitives()

    test_res_array = []

    @sio.on('monitoring', namespace='/status')
    def on_monitoring(data):
        # Confirmation that we are waiting for status messages
        test_res_array.append(('on_monitoring', data == monitoring))

    @sio.on('AlerterHeartbeat', namespace='/status')
    def on_alerter_heartbeat(data):
        test_res_array.append(('on_alerter_heartbeat', data == alerter_hb_msg['msg']))

    @sio.on('DispatcherHeartbeat', namespace='/status')
    def on_dispatcher_heartbeat(data):
        test_res_array.append(('on_dispatcher_heartbeat', data == dispatcher_hb_msg['msg']))

    @sio.on('ExpiryHeartbeat', namespace='/status')
    def on_expiry_heartbeat(data):
        test_res_array.append(('on_expiry_heartbeat', data == expiry_hb_msg['msg']))

    @sio.on('IngestHeartbeat', namespace='/status')
    def on_ingest_heartbeat(data):
        test_res_array.append(('on_ingest_heartbeat', data == ingest_hb_msg['msg']))

    @sio.on('ServiceHeartbeat', namespace='/status')
    def on_service_heartbeat(data):
        test_res_array.append(('on_service_heartbeat', data == service_hb_msg['msg']))

    @sio.on('ServiceTimingHeartbeat', namespace='/status')
    def on_service_timing_heartbeat(data):
        test_res_array.append(('on_service_timing_heartbeat', data == service_timing_msg['msg']))

    try:
        sio.emit('monitor', monitoring, namespace='/status')
        sio.sleep(1)

        status_queue.publish(alerter_hb_msg)
        status_queue.publish(dispatcher_hb_msg)
        status_queue.publish(expiry_hb_msg)
        status_queue.publish(ingest_hb_msg)
        status_queue.publish(service_hb_msg)
        status_queue.publish(service_timing_msg)

        start_time = time.time()

        while len(test_res_array) < 7 and time.time() - start_time < 5:
            sio.sleep(0.1)

        assert len(test_res_array) == 7

        for test, result in test_res_array:
            if not result:
                pytest.fail(f"{test} failed.")
    finally:
        sio.disconnect()


# noinspection PyUnusedLocal
def test_submission(datastore, sio):
    submission_queue = CommsQueue('submissions', private=True)
    monitoring = get_random_id()

    ingested = random_model_obj(SubmissionMessage).as_primitives()
    ingested['msg_type'] = "SubmissionIngested"
    received = random_model_obj(SubmissionMessage).as_primitives()
    received['msg_type'] = "SubmissionReceived"
    queued = random_model_obj(SubmissionMessage).as_primitives()
    queued['msg_type'] = "SubmissionQueued"
    started = random_model_obj(SubmissionMessage).as_primitives()
    started['msg_type'] = "SubmissionStarted"

    test_res_array = []

    @sio.on('monitoring', namespace='/submissions')
    def on_monitoring(data):
        # Confirmation that we are waiting for status messages
        test_res_array.append(('on_monitoring', data == monitoring))

    @sio.on('SubmissionIngested', namespace='/submissions')
    def on_submission_ingested(data):
        test_res_array.append(('on_submission_ingested', data == ingested['msg']))

    @sio.on('SubmissionReceived', namespace='/submissions')
    def on_submission_received(data):
        test_res_array.append(('on_submission_received', data == received['msg']))

    @sio.on('SubmissionQueued', namespace='/submissions')
    def on_submission_queued(data):
        test_res_array.append(('on_submission_queued', data == queued['msg']))

    @sio.on('SubmissionStarted', namespace='/submissions')
    def on_submission_started(data):
        test_res_array.append(('on_submission_started', data == started['msg']))

    try:
        sio.emit('monitor', monitoring, namespace='/submissions')
        sio.sleep(1)

        submission_queue.publish(ingested)
        submission_queue.publish(received)
        submission_queue.publish(queued)
        submission_queue.publish(started)

        start_time = time.time()

        while len(test_res_array) < 5 and time.time() - start_time < 5:
            sio.sleep(0.1)

        assert len(test_res_array) == 5

        for test, result in test_res_array:
            if not result:
                pytest.fail(f"{test} failed.")
    finally:
        sio.disconnect()
