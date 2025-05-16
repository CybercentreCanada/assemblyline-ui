import base64
import hashlib
import json
import os
import tempfile

import pytest
from assemblyline_core.ingester.constants import INGEST_QUEUE_NAME
from conftest import APIError, get_api_data

from assemblyline.common import forge
from assemblyline.odm.messages.submission import Submission
from assemblyline.odm.models.config import DEFAULT_SUBMISSION_PROFILES, HASH_PATTERN_MAP
from assemblyline.odm.models.file import File
from assemblyline.odm.random_data import (
    create_services,
    create_users,
    wipe_services,
    wipe_users,
)
from assemblyline.odm.randomizer import get_random_phrase, random_model_obj
from assemblyline.remote.datatypes.queues.named import NamedQueue

NUM_FILES = 4
TEST_QUEUE = "my_queue"
config = forge.get_config()
nq = NamedQueue(f"nq-{TEST_QUEUE}", host=config.core.redis.persistent.host,
                port=config.core.redis.persistent.port)
iq = NamedQueue(INGEST_QUEUE_NAME, host=config.core.redis.persistent.host,
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
    fileinfo = get_api_data(session, f"{host}/api/v4/search/file/?query=*&fl={hash}&rows=1")['items'][0]
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

def test_ingest_metadata_validation(datastore, login_session):
    _, session, host = login_session

    iq.delete()

    byte_str = get_random_phrase(wmin=30, wmax=75).encode()
    sha256 = hashlib.sha256(byte_str).hexdigest()

    # Test with strict metadata validation that should pass
    data = {
        'base64': base64.b64encode(byte_str).decode('ascii'),
        'metadata': {'test': 'ingest_base64_nameless'},
        "params": {'type': 'strict_ingest'}
    }
    resp = get_api_data(session, f"{host}/api/v4/ingest/", method="POST", data=json.dumps(data))
    assert isinstance(resp['ingest_id'], str)

    # Test with strict metadata validation that should fail due to extra metadata
    with pytest.raises(APIError, match="Extra metadata found from submission"):
        data['metadata'] = {'test': 'ingest_base64_nameless', 'blah': 'blah'}
        get_api_data(session, f"{host}/api/v4/ingest/", method="POST", data=json.dumps(data))

    # Test with metadata validation against a scheme that's not known to the system
    # This should succeed because there is no scheme to enforce validation
    data["params"] = {'type': 'blah'}
    resp = get_api_data(session, f"{host}/api/v4/ingest/", method="POST", data=json.dumps(data))
    assert isinstance(resp['ingest_id'], str)

    # Test submitting with a submission profile that has the ingest type preset
    # With currently set metadata, this should raise an API error
    with pytest.raises(APIError, match="Extra metadata found from submission"):
        data.pop('params')
        data['submission_profile'] = "static"
        get_api_data(session, f"{host}/api/v4/ingest/", method="POST", data=json.dumps(data))

    # Fix metadata and resubmit (still using a submission profile)
    data['metadata'].pop('blah')
    resp = get_api_data(session, f"{host}/api/v4/ingest/", method="POST", data=json.dumps(data))
    assert isinstance(resp['ingest_id'], str)



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

def test_ingest_submission_profile(datastore, login_session, scheduler):
    _, session, host = login_session
    iq.delete()

    # Make the user a simple user and try to submit
    datastore.user.update('admin', [
        (datastore.user.UPDATE_REMOVE, 'type', 'admin'),
        (datastore.user.UPDATE_APPEND, 'roles', 'submission_create')])
    byte_str = get_random_phrase(wmin=30, wmax=75).encode()
    data = {
        'base64': base64.b64encode(byte_str).decode('ascii'),
        'metadata': {'test': 'test_submit_base64_nameless'}
    }
    with pytest.raises(APIError, match="You must specify a submission profile"):
        # A basic user must specify a submission profile name
        get_api_data(session, f"{host}/api/v4/ingest/", method="POST", data=json.dumps(data))

    # Try using a submission profile with no parameters
    profile = DEFAULT_SUBMISSION_PROFILES[0]
    data['submission_profile'] = profile["name"]
    get_api_data(session, f"{host}/api/v4/ingest/", method="POST", data=json.dumps(data))

    # Try using a submission profile with a change to the service selection
    data['params'] = {'services': {'selected': ['blah']}}
    # But also try setting a parameter that you are allowed to set
    data['params'] = {'deep_scan': True}
    get_api_data(session, f"{host}/api/v4/ingest/", method="POST", data=json.dumps(data))

    # Restore original roles for later tests
    datastore.user.update('admin', [(datastore.user.UPDATE_APPEND, 'type', 'admin'),])
