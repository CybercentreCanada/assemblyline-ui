import base64
import json
import random

import pytest

# noinspection PyUnresolvedReferences
from base import HOST, login_session, get_api_data, create_users, wipe_users, create_services, wipe_services

from assemblyline.common import forge
from assemblyline.odm.messages.submission import Submission
from assemblyline.odm.models.file import File
from assemblyline.odm.randomizer import random_model_obj
from assemblyline.remote.datatypes.queues.named import NamedQueue

NUM_FILES = 4
TEST_QUEUE = "my_queue"
config = forge.get_config()
ds = forge.get_datastore(config)
fs = forge.get_filestore(config)
nq = NamedQueue(f"nq-{TEST_QUEUE}", host=config.core.redis.persistent.host,
                port=config.core.redis.persistent.port, db=config.core.redis.persistent.db)
iq = NamedQueue("m-ingest", host=config.core.redis.persistent.host,
                port=config.core.redis.persistent.port, db=config.core.redis.persistent.db)
file_hashes = []


def purge_ingest():
    # Cleanup Elastic
    ds.file.wipe()
    wipe_services(ds)
    wipe_users(ds)

    # Cleanup Minio
    for f in file_hashes:
        fs.delete(f)

    # Cleanup Redis
    nq.delete()
    iq.delete()


@pytest.fixture(scope="module")
def datastore(request):
    create_users(ds)
    create_services(ds)

    for _ in range(NUM_FILES):
        f = random_model_obj(File)
        ds.file.save(f.sha256, f)
        file_hashes.append(f.sha256)
        fs.put(f.sha256, f.sha256)

    ds.file.commit()

    request.addfinalizer(purge_ingest)
    return ds



# noinspection PyUnusedLocal
def test_ingest_hash(datastore, login_session):
    _, session = login_session

    data = {
        'sha256': random.choice(file_hashes),
        'name': 'random_hash.txt',
        'metadata': {'test': 'ingest_hash'},
        'notification_queue': TEST_QUEUE
    }
    resp = get_api_data(session, f"{HOST}/api/v4/ingest/", method="POST", data=json.dumps(data))
    assert isinstance(resp['ingest_id'], str)

    msg = Submission(iq.pop(blocking=False))
    assert msg.metadata['ingest_id'] == resp['ingest_id']


# noinspection PyUnusedLocal
def test_ingest_url(datastore, login_session):
    _, session = login_session

    data = {
        'url': 'https://www.cyber.gc.ca/en/theme-gcwu-fegc/assets/wmms.svg',
        'name': 'wmms.svg',
        'metadata': {'test': 'ingest_url'},
        'notification_queue': TEST_QUEUE
    }
    resp = get_api_data(session, f"{HOST}/api/v4/ingest/", method="POST", data=json.dumps(data))
    assert isinstance(resp['ingest_id'], str)

    msg = Submission(iq.pop(blocking=False))
    assert msg.metadata['ingest_id'] == resp['ingest_id']


# noinspection PyUnusedLocal
def test_ingest_binary(datastore, login_session):
    _, session = login_session

    data = {
        'binary': base64.b64encode(b"THIS IS THE DATA I HAVE IN MY FILE!!!!!!!!!").decode(),
        'name': 'text.txt',
        'metadata': {'test': 'ingest_binary'},
        'notification_queue': TEST_QUEUE
    }
    resp = get_api_data(session, f"{HOST}/api/v4/ingest/", method="POST", data=json.dumps(data))
    assert isinstance(resp['ingest_id'], str)

    msg = Submission(iq.pop(blocking=False))
    assert msg.metadata['ingest_id'] == resp['ingest_id']


# noinspection PyUnusedLocal
def test_get_message(datastore, login_session):
    _, session = login_session

    test_message = random_model_obj(Submission).as_primitives()
    nq.push(test_message)

    resp = get_api_data(session, f"{HOST}/api/v4/ingest/get_message/{TEST_QUEUE}/")
    assert resp == test_message


# noinspection PyUnusedLocal
def test_get_message_list(datastore, login_session):
    _, session = login_session

    messages = []
    for x in range(NUM_FILES):
        test_message = random_model_obj(Submission).as_primitives()
        messages.append(test_message)
        nq.push(test_message)

    resp = get_api_data(session, f"{HOST}/api/v4/ingest/get_message_list/{TEST_QUEUE}/")
    for x in range(NUM_FILES):
        assert resp[x] == messages[x]
