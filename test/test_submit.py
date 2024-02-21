import base64
import hashlib
import json
import os
import pytest
import random
import tempfile

from conftest import get_api_data

from assemblyline.common import forge
from assemblyline.odm.random_data import create_users, wipe_users, create_submission, wipe_submissions
from assemblyline.odm.randomizer import get_random_phrase
from assemblyline.remote.datatypes.queues.named import NamedQueue
from assemblyline_core.dispatching.dispatcher import SubmissionTask

config = forge.get_config()
sq = NamedQueue('dispatch-submission-queue', host=config.core.redis.persistent.host,
                port=config.core.redis.persistent.port)
submission = None


@pytest.fixture(scope="module")
def datastore(datastore_connection, filestore):
    global submission
    try:
        create_users(datastore_connection)
        submission = create_submission(datastore_connection, filestore)
        yield datastore_connection
    finally:
        wipe_users(datastore_connection)
        wipe_submissions(datastore_connection, filestore)
        sq.delete()


# noinspection PyUnusedLocal
def test_resubmit(datastore, login_session, scheduler):
    _, session, host = login_session

    sq.delete()
    submission_files = [f.sha256 for f in submission.files]
    resp = get_api_data(session, f"{host}/api/v4/submit/resubmit/{submission.sid}/")
    assert resp['params']['description'].startswith('Resubmit')
    assert resp['sid'] != submission.sid
    for f in resp['files']:
        assert f['sha256'] in submission_files

    msg = SubmissionTask(scheduler=scheduler, datastore=datastore, **sq.pop(blocking=False))
    assert msg.submission.sid == resp['sid']


# noinspection PyUnusedLocal
def test_resubmit_dynamic(datastore, login_session, scheduler):
    _, session, host = login_session

    sq.delete()
    sha256 = random.choice(submission.results)[:64]
    resp = get_api_data(session, f"{host}/api/v4/submit/dynamic/{sha256}/")
    assert resp['params']['description'].startswith('Resubmit')
    assert resp['params']['description'].endswith('Dynamic Analysis')
    assert resp['sid'] != submission.sid
    for f in resp['files']:
        assert f['sha256'] == sha256
    assert 'Dynamic Analysis' in resp['params']['services']['selected']

    msg = SubmissionTask(scheduler=scheduler, datastore=datastore, **sq.pop(blocking=False))
    assert msg.submission.sid == resp['sid']


# noinspection PyUnusedLocal
def test_submit_hash(datastore, login_session, scheduler):
    _, session, host = login_session

    sq.delete()
    data = {
        'sha256': random.choice(submission.results)[:64],
        'name': 'random_hash.txt',
        'metadata': {'test': 'test_submit_hash'}
    }
    resp = get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=json.dumps(data))
    assert isinstance(resp['sid'], str)
    for f in resp['files']:
        assert f['sha256'] == data['sha256']
        assert f['name'] == data['name']

    msg = SubmissionTask(scheduler=scheduler, datastore=datastore, **sq.pop(blocking=False))
    assert msg.submission.sid == resp['sid']


# noinspection PyUnusedLocal
def test_submit_url(datastore, login_session, scheduler):
    _, session, host = login_session

    sq.delete()
    data = {
        'url': 'https://raw.githubusercontent.com/CybercentreCanada/assemblyline-ui/master/README.md',
        'name': 'README.md',
        'metadata': {'test': 'test_submit_url'}
    }
    resp = get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=json.dumps(data))
    assert isinstance(resp['sid'], str)
    for f in resp['files']:
        assert f['name'] == data['url']  # The name is overwritten for URIs

    msg = SubmissionTask(scheduler=scheduler, datastore=datastore, **sq.pop(blocking=False))
    assert msg.submission.sid == resp['sid']

# noinspection PyUnusedLocal
def test_submit_defanged_url(datastore, login_session, scheduler):
    _, session, host = login_session

    sq.delete()
    data = {
        'url': 'hxxps://raw[.]githubusercontent[.]com/CybercentreCanada/assemblyline-ui/master/README[.]md',
        'name': 'README.md',
        'metadata': {'test': 'test_submit_url'}
    }
    resp = get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=json.dumps(data))
    assert isinstance(resp['sid'], str)
    for f in resp['files']:
        # The name is overwritten for URIs
        assert f['name'] == 'https://raw.githubusercontent.com/CybercentreCanada/assemblyline-ui/master/README.md'

    msg = SubmissionTask(scheduler=scheduler, datastore=datastore, **sq.pop(blocking=False))
    assert msg.submission.sid == resp['sid']


# noinspection PyUnusedLocal
def test_submit_binary(datastore, login_session, scheduler):
    _, session, host = login_session

    sq.delete()
    byte_str = get_random_phrase(wmin=30, wmax=75).encode()
    fd, temp_path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, 'wb') as fh:
            fh.write(byte_str)

        with open(temp_path, 'rb') as fh:
            sha256 = hashlib.sha256(byte_str).hexdigest()
            json_data = {
                'name': 'binary.txt',
                'metadata': {'test': 'test_submit_binary'}
            }
            data = {'json': json.dumps(json_data)}
            resp = get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=data,
                                files={'bin': fh}, headers={})

        assert isinstance(resp['sid'], str)
        for f in resp['files']:
            assert f['sha256'] == sha256
            assert f['name'] == json_data['name']

        msg = SubmissionTask(scheduler=scheduler, datastore=datastore, **sq.pop(blocking=False))
        assert msg.submission.sid == resp['sid']

    finally:
        # noinspection PyBroadException
        try:
            os.unlink(temp_path)
        except Exception:
            pass

# noinspection PyUnusedLocal
def test_submit_binary_nameless(datastore, login_session, scheduler):
    _, session, host = login_session

    sq.delete()
    byte_str = get_random_phrase(wmin=30, wmax=75).encode()
    fd, temp_path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, 'wb') as fh:
            fh.write(byte_str)

        with open(temp_path, 'rb') as fh:
            sha256 = hashlib.sha256(byte_str).hexdigest()
            json_data = {
                'metadata': {'test': 'test_submit_binary_nameless'}
            }
            data = {'json': json.dumps(json_data)}
            resp = get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=data,
                                files={'bin': fh}, headers={})

        assert isinstance(resp['sid'], str)
        for f in resp['files']:
            assert f['sha256'] == sha256
            assert f['name'] == os.path.basename(temp_path)

        msg = SubmissionTask(scheduler=scheduler, datastore=datastore, **sq.pop(blocking=False))
        assert msg.submission.sid == resp['sid']

    finally:
        # noinspection PyBroadException
        try:
            os.unlink(temp_path)
        except Exception:
            pass


# noinspection PyUnusedLocal
def test_submit_plaintext(datastore, login_session, scheduler):
    _, session, host = login_session

    sq.delete()
    plain_str = get_random_phrase(wmin=30, wmax=75)
    sha256 = hashlib.sha256(plain_str.encode()).hexdigest()
    data = {
        'name': 'plain.txt',
        'plaintext': plain_str,
        'metadata': {'test': 'test_submit_plaintext'}
    }
    resp = get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=json.dumps(data))
    assert isinstance(resp['sid'], str)
    for f in resp['files']:
        assert f['sha256'] == sha256
        assert f['name'] == data['name']

    msg = SubmissionTask(scheduler=scheduler, datastore=datastore, **sq.pop(blocking=False))
    assert msg.submission.sid == resp['sid']

# noinspection PyUnusedLocal
def test_submit_plaintext_nameless(datastore, login_session, scheduler):
    _, session, host = login_session

    sq.delete()
    plain_str = get_random_phrase(wmin=30, wmax=75)
    sha256 = hashlib.sha256(plain_str.encode()).hexdigest()
    data = {
        'plaintext': plain_str,
        'metadata': {'test': 'test_submit_plaintext_nameless'}
    }
    resp = get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=json.dumps(data))
    assert isinstance(resp['sid'], str)
    for f in resp['files']:
        assert f['sha256'] == sha256
        assert f['name'] == sha256

    msg = SubmissionTask(scheduler=scheduler, datastore=datastore, **sq.pop(blocking=False))
    assert msg.submission.sid == resp['sid']


# noinspection PyUnusedLocal
def test_submit_base64(datastore, login_session, scheduler):
    _, session, host = login_session

    sq.delete()
    byte_str = get_random_phrase(wmin=30, wmax=75).encode()
    sha256 = hashlib.sha256(byte_str).hexdigest()
    data = {
        'name': 'base64.txt',
        'base64': base64.b64encode(byte_str).decode('ascii'),
        'metadata': {'test': 'test_submit_base64'}
    }
    resp = get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=json.dumps(data))
    assert isinstance(resp['sid'], str)
    for f in resp['files']:
        assert f['sha256'] == sha256
        assert f['name'] == data['name']

    msg = SubmissionTask(scheduler=scheduler, datastore=datastore, **sq.pop(blocking=False))
    assert msg.submission.sid == resp['sid']

# noinspection PyUnusedLocal
def test_submit_base64_nameless(datastore, login_session, scheduler):
    _, session, host = login_session

    sq.delete()
    byte_str = get_random_phrase(wmin=30, wmax=75).encode()
    sha256 = hashlib.sha256(byte_str).hexdigest()
    data = {
        'base64': base64.b64encode(byte_str).decode('ascii'),
        'metadata': {'test': 'test_submit_base64_nameless'}
    }
    resp = get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=json.dumps(data))
    assert isinstance(resp['sid'], str)
    for f in resp['files']:
        assert f['sha256'] == sha256
        assert f['name'] == sha256

    msg = SubmissionTask(scheduler=scheduler, datastore=datastore, **sq.pop(blocking=False))
    assert msg.submission.sid == resp['sid']
