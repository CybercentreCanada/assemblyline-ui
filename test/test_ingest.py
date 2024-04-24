import base64
import hashlib
import json
import os
import pytest
import random
import tempfile

from conftest import get_api_data

from assemblyline.common import forge
from assemblyline.odm.messages.submission import Submission
from assemblyline.odm.models.config import HASH_PATTERN_MAP
from assemblyline.odm.models.file import File
from assemblyline.odm.randomizer import random_model_obj, get_random_phrase
from assemblyline.odm.random_data import create_users, wipe_users, create_services, wipe_services
from assemblyline.remote.datatypes.queues.named import NamedQueue

NUM_FILES = 4
TEST_QUEUE = "my_queue"
config = forge.get_config()
nq = NamedQueue(f"nq-{TEST_QUEUE}", host=config.core.redis.persistent.host,
                port=config.core.redis.persistent.port)
iq = NamedQueue("m-ingest", host=config.core.redis.persistent.host,
                port=config.core.redis.persistent.port)
file_hashes = []


@pytest.fixture(scope="module")
def datastore(datastore_connection, filestore):
    ds = datastore_connection
    try:
        create_users(ds)
        create_services(ds)

        for _ in range(NUM_FILES):
            f = random_model_obj(File)
            ds.file.save(f.sha256, f)
            file_hashes.append(f.sha256)
            filestore.put(f.sha256, f.sha256)

        ds.file.commit()
        yield ds
    finally:
        # Cleanup Elastic
        ds.file.wipe()
        wipe_services(ds)
        wipe_users(ds)

        # Cleanup Minio
        for f in file_hashes:
            filestore.delete(f)

        # Cleanup Redis
        nq.delete()
        iq.delete()


# noinspection PyUnusedLocal
@pytest.mark.parametrize("hash", list(HASH_PATTERN_MAP.keys()))
def test_ingest_hash(datastore, login_session, hash):
    _, session, host = login_session

    iq.delete()
    # Look for any file where the hash of that file is set
    fileinfo = datastore.file.search(f"{hash}:*", rows=1, fl=hash, as_obj=False)['items'][0]
    data = {
        hash: fileinfo[hash],
        'name': 'random_hash.txt',
        'metadata': {'test': 'ingest_hash'},
        'notification_queue': TEST_QUEUE
    }
    resp = get_api_data(session, f"{host}/api/v4/ingest/", method="POST", data=json.dumps(data))
    assert isinstance(resp['ingest_id'], str)

    msg = Submission(iq.pop(blocking=False))
    assert msg.metadata['ingest_id'] == resp['ingest_id']


# noinspection PyUnusedLocal
def test_ingest_url(datastore, login_session):
    _, session, host = login_session

    iq.delete()
    data = {
        'url': 'https://raw.githubusercontent.com/CybercentreCanada/assemblyline-ui/master/README.md',
        'name': 'README.md',
        'metadata': {'test': 'ingest_url'},
        'notification_queue': TEST_QUEUE
    }
    resp = get_api_data(session, f"{host}/api/v4/ingest/", method="POST", data=json.dumps(data))
    assert isinstance(resp['ingest_id'], str)

    msg = Submission(iq.pop(blocking=False))
    assert msg.metadata['ingest_id'] == resp['ingest_id']
    for f in msg['files']:
        # The name is overwritten for URIs
        assert f['name'] == 'https://raw.githubusercontent.com/CybercentreCanada/assemblyline-ui/master/README.md'

# noinspection PyUnusedLocal
def test_ingest_defanged_url(datastore, login_session):
    _, session, host = login_session

    iq.delete()
    data = {
        'url': 'hxxps://raw[.]githubusercontent[.]com/CybercentreCanada/assemblyline-ui/master/README[.]md',
        'name': 'README.md',
        'metadata': {'test': 'ingest_url'},
        'notification_queue': TEST_QUEUE
    }
    resp = get_api_data(session, f"{host}/api/v4/ingest/", method="POST", data=json.dumps(data))
    assert isinstance(resp['ingest_id'], str)

    msg = Submission(iq.pop(blocking=False))
    assert msg.metadata['ingest_id'] == resp['ingest_id']
    for f in msg['files']:
        # The name is overwritten for URIs
        assert f['name'] == 'https://raw.githubusercontent.com/CybercentreCanada/assemblyline-ui/master/README.md'


# noinspection PyUnusedLocal
def test_ingest_binary(datastore, login_session):
    _, session, host = login_session

    iq.delete()

    byte_str = get_random_phrase(wmin=30, wmax=75).encode()
    fd, temp_path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, 'wb') as fh:
            fh.write(byte_str)

        with open(temp_path, 'rb') as fh:
            sha256 = hashlib.sha256(byte_str).hexdigest()
            json_data = {
                'name': 'binary.txt',
                'metadata': {'test': 'ingest_binary'},
                'notification_queue': TEST_QUEUE
            }
            data = {'json': json.dumps(json_data)}
            resp = get_api_data(session, f"{host}/api/v4/ingest/", method="POST", data=data,
                                files={'bin': fh}, headers={})

        assert isinstance(resp['ingest_id'], str)

        msg = Submission(iq.pop(blocking=False))
        assert msg.metadata['ingest_id'] == resp['ingest_id']
        assert msg.files[0].sha256 == sha256
        assert msg.files[0].name == json_data['name']

    finally:
        # noinspection PyBroadException
        try:
            os.unlink(temp_path)
        except Exception:
            pass

# noinspection PyUnusedLocal
def test_ingest_binary_nameless(datastore, login_session):
    _, session, host = login_session

    iq.delete()

    byte_str = get_random_phrase(wmin=30, wmax=75).encode()
    fd, temp_path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, 'wb') as fh:
            fh.write(byte_str)

        with open(temp_path, 'rb') as fh:
            sha256 = hashlib.sha256(byte_str).hexdigest()
            json_data = {
                'metadata': {'test': 'ingest_binary_nameless'},
                'notification_queue': TEST_QUEUE
            }
            data = {'json': json.dumps(json_data)}
            resp = get_api_data(session, f"{host}/api/v4/ingest/", method="POST", data=data,
                                files={'bin': fh}, headers={})

        assert isinstance(resp['ingest_id'], str)

        msg = Submission(iq.pop(blocking=False))
        assert msg.metadata['ingest_id'] == resp['ingest_id']
        assert msg.files[0].sha256 == sha256
        assert msg.files[0].name == os.path.basename(temp_path)

    finally:
        # noinspection PyBroadException
        try:
            os.unlink(temp_path)
        except Exception:
            pass


# noinspection PyUnusedLocal
def test_ingest_plaintext(datastore, login_session):
    _, session, host = login_session

    iq.delete()

    plain_str = get_random_phrase(wmin=30, wmax=75)
    sha256 = hashlib.sha256(plain_str.encode()).hexdigest()
    data = {
        'name': 'plain.txt',
        'plaintext': plain_str,
        'metadata': {'test': 'ingest_plaintext'},
        'notification_queue': TEST_QUEUE
    }
    resp = get_api_data(session, f"{host}/api/v4/ingest/", method="POST", data=json.dumps(data))
    assert isinstance(resp['ingest_id'], str)

    msg = Submission(iq.pop(blocking=False))
    assert msg.metadata['ingest_id'] == resp['ingest_id']
    assert msg.files[0].sha256 == sha256
    assert msg.files[0].name == data['name']

# noinspection PyUnusedLocal
def test_ingest_plaintext_nameless(datastore, login_session):
    _, session, host = login_session

    iq.delete()

    plain_str = get_random_phrase(wmin=30, wmax=75)
    sha256 = hashlib.sha256(plain_str.encode()).hexdigest()
    data = {
        'plaintext': plain_str,
        'metadata': {'test': 'ingest_plaintext_nameless'},
        'notification_queue': TEST_QUEUE
    }
    resp = get_api_data(session, f"{host}/api/v4/ingest/", method="POST", data=json.dumps(data))
    assert isinstance(resp['ingest_id'], str)

    msg = Submission(iq.pop(blocking=False))
    assert msg.metadata['ingest_id'] == resp['ingest_id']
    assert msg.files[0].sha256 == sha256
    assert msg.files[0].name == sha256


# noinspection PyUnusedLocal
def test_ingest_base64(datastore, login_session):
    _, session, host = login_session

    iq.delete()

    byte_str = get_random_phrase(wmin=30, wmax=75).encode()
    sha256 = hashlib.sha256(byte_str).hexdigest()
    data = {
        'name': 'plain.txt',
        'base64': base64.b64encode(byte_str).decode('ascii'),
        'metadata': {'test': 'ingest_base64'},
        'notification_queue': TEST_QUEUE
    }
    resp = get_api_data(session, f"{host}/api/v4/ingest/", method="POST", data=json.dumps(data))
    assert isinstance(resp['ingest_id'], str)

    msg = Submission(iq.pop(blocking=False))
    assert msg.metadata['ingest_id'] == resp['ingest_id']
    assert msg.files[0].sha256 == sha256
    assert msg.files[0].name == data['name']

# noinspection PyUnusedLocal
def test_ingest_base64_nameless(datastore, login_session):
    _, session, host = login_session

    iq.delete()

    byte_str = get_random_phrase(wmin=30, wmax=75).encode()
    sha256 = hashlib.sha256(byte_str).hexdigest()
    data = {
        'base64': base64.b64encode(byte_str).decode('ascii'),
        'metadata': {'test': 'ingest_base64_nameless'},
        'notification_queue': TEST_QUEUE
    }
    resp = get_api_data(session, f"{host}/api/v4/ingest/", method="POST", data=json.dumps(data))
    assert isinstance(resp['ingest_id'], str)

    msg = Submission(iq.pop(blocking=False))
    assert msg.metadata['ingest_id'] == resp['ingest_id']
    assert msg.files[0].sha256 == sha256
    assert msg.files[0].name == sha256


# noinspection PyUnusedLocal
def test_get_message(datastore, login_session):
    _, session, host = login_session

    nq.delete()
    test_message = random_model_obj(Submission).as_primitives()
    nq.push(test_message)

    resp = get_api_data(session, f"{host}/api/v4/ingest/get_message/{TEST_QUEUE}/")
    assert resp == test_message


# noinspection PyUnusedLocal
def test_get_message_list(datastore, login_session):
    _, session, host = login_session

    nq.delete()
    messages = []
    for x in range(NUM_FILES):
        test_message = random_model_obj(Submission).as_primitives()
        messages.append(test_message)
        nq.push(test_message)

    resp = get_api_data(session, f"{host}/api/v4/ingest/get_message_list/{TEST_QUEUE}/")
    for x in range(NUM_FILES):
        assert resp[x] == messages[x]

# noinspection PyUnusedLocal
def test_get_message_list_with_paging(datastore, login_session):
    _, session, host = login_session

    nq.delete()
    messages = []
    for x in range(NUM_FILES):
        test_message = random_model_obj(Submission).as_primitives()
        messages.append(test_message)
        nq.push(test_message)

    message_list = []
    resp = True
    while resp:
        # Page through the notification queue with a page_size of 2
        resp = get_api_data(session, f"{host}/api/v4/ingest/get_message_list/{TEST_QUEUE}/?page_size=2")
        message_list += resp
    for x in range(NUM_FILES):
        assert message_list[x] == messages[x]
