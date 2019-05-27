import pytest
import requests
import socketio
import time


from assemblyline.common import forge
from assemblyline.common.uid import get_random_id
from assemblyline.odm.messages.alert import AlertMessage
from assemblyline.odm.randomizer import random_model_obj
from assemblyline.remote.datatypes.queues.comms import CommsQueue

# noinspection PyUnresolvedReferences
from base import get_api_data

from assemblyline.remote.datatypes.queues.named import NamedQueue

config = forge.get_config()
ds = forge.get_datastore()
alert_queue = CommsQueue('alerts', private=True, host=config.core.redis.persistent.host,
                         port=config.core.redis.persistent.port, db=config.core.redis.persistent.db)


def purge_socket():
    pass

@pytest.fixture(scope='function')
def login_session():
    session = requests.Session()
    data = get_api_data(session, f"http://localhost:5000/api/v4/auth/login/",
                        params={'user': 'admin', 'password': 'admin'})
    return data, session

@pytest.fixture(scope="module")
def datastore(request):
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
    test_id = get_random_id()

    created = random_model_obj(AlertMessage)
    created.msg_type = "AlertCreated"

    updated = random_model_obj(AlertMessage)
    updated.msg_type = "AlertUpdated"

    test_res_array = []

    @sio.on('monitoring', namespace='/alerts')
    def on_monitoring(data):
        # Confirmation that we are waiting for alerts
        if data == test_id:
            test_res_array.append(('on_monitoring', True))
        else:
            test_res_array.append(('on_monitoring', False))

    @sio.on('AlertCreated', namespace='/alerts')
    def on_alert_created(data):
        if data == created.as_primitives()['msg']:
            test_res_array.append(('on_alert_created', True))
        else:
            test_res_array.append(('on_alert_created', False))

    @sio.on('AlertUpdated', namespace='/alerts')
    def on_alert_updated(data):
        if data == updated.as_primitives()['msg']:
            test_res_array.append(('on_alert_updated', True))
        else:
            test_res_array.append(('on_alert_updated', False))


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

    sio.disconnect()


# noinspection PyUnusedLocal
def test_live_namespace(datastore, sio):
    wq_data = {'wq_id': get_random_id()}
    wq = NamedQueue(wq_data['wq_id'], private=True, host=config.core.redis.persistent.host,
                    port=config.core.redis.persistent.port, db=config.core.redis.persistent.db)

    start_msg = {'status_code': 200, 'msg': "Start listening..."}
    stop_msg = {'status_code': 200, 'msg': "All messages received, closing queue..."}
    cachekey_msg = {'status_code': 200, 'msg': get_random_id()}
    cachekeyerr_msg = {'status_code': 200, 'msg': get_random_id()}

    test_res_array = []

    @sio.on('start', namespace='/live_submission')
    def on_start(data):
        # Confirmation that we are waiting for alerts
        if data == start_msg:
            test_res_array.append(('on_start', True))
        else:
            test_res_array.append(('on_start', False))

    @sio.on('stop', namespace='/live_submission')
    def on_stop(data):
        # Confirmation that we are waiting for alerts
        if data == stop_msg:
            test_res_array.append(('on_stop', True))
        else:
            test_res_array.append(('on_stop', False))

    @sio.on('cachekey', namespace='/live_submission')
    def on_cachekey(data):
        # Confirmation that we are waiting for alerts
        if data == cachekey_msg:
            test_res_array.append(('on_cachekey', True))
        else:
            test_res_array.append(('on_cachekey', False))

    @sio.on('cachekeyerr', namespace='/live_submission')
    def on_stop(data):
        # Confirmation that we are waiting for alerts
        if data == cachekeyerr_msg:
            test_res_array.append(('on_cachekeyerr', True))
        else:
            test_res_array.append(('on_cachekeyerr', False))


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

    sio.disconnect()