import pytest

from conftest import get_api_data

from assemblyline.common import forge
from assemblyline.odm.models.result import Result
from assemblyline.odm.models.submission import Submission
from assemblyline.odm.randomizer import random_model_obj
from assemblyline.odm.random_data import create_users, wipe_users
from assemblyline.remote.datatypes.queues.named import NamedQueue

config = forge.get_config()
test_submission = None
wq_id = "D-test_watch_queue-WQ"
wq = NamedQueue(wq_id, host=config.core.redis.persistent.host,
                port=config.core.redis.persistent.port)


@pytest.fixture(scope="module")
def datastore(datastore_connection):
    global test_submission
    try:
        create_users(datastore_connection)

        test_submission = random_model_obj(Submission)
        datastore_connection.submission.save(test_submission.sid, test_submission)
        datastore_connection.submission.commit()
        yield datastore_connection
    finally:
        datastore_connection.submission.wipe()
        wipe_users(datastore_connection)


# noinspection PyUnusedLocal
def test_get_message(datastore, login_session):
    _, session, host = login_session

    r = random_model_obj(Result)
    wq.push({'status': "OK", 'cache_key': r.build_key()})
    resp = get_api_data(session, f"{host}/api/v4/live/get_message/{wq_id}/")
    assert resp['msg'] == r.build_key()


# noinspection PyUnusedLocal
def test_get_message_list(datastore, login_session):
    _, session, host = login_session

    msgs = []
    for x in range(10):
        r = random_model_obj(Result)
        wq.push({'status': "OK", 'cache_key': r.build_key()})
        msgs.append(r.build_key())

    resp = get_api_data(session, f"{host}/api/v4/live/get_message_list/{wq_id}/")
    for x in range(10):
        assert resp[x]['msg'] == msgs[x]


# noinspection PyUnusedLocal
def test_outstanding_services(datastore, login_session):
    _, session, host = login_session

    resp = get_api_data(session, f"{host}/api/v4/live/outstanding_services/{test_submission.sid}/")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_setup_watch_queue(datastore, login_session):
    _, session, host = login_session

    resp = get_api_data(session, f"{host}/api/v4/live/setup_watch_queue/{test_submission.sid}/")
    assert resp['wq_id'].startswith("D-") and resp['wq_id'].endswith("-WQ")

    resp = get_api_data(session, f"{host}/api/v4/live/get_message/{resp['wq_id']}/")
    assert resp['type'] == 'start'
