import base64
import hashlib
import json
import random

import pytest

from base import HOST, login_session, get_api_data

from al_core.dispatching.dispatcher import SubmissionTask
from assemblyline.common import forge
from assemblyline.odm.randomizer import get_random_phrase
from assemblyline.odm.random_data import create_users, wipe_users, create_submission, wipe_submissions
from assemblyline.remote.datatypes.queues.named import NamedQueue

config = forge.get_config()
ds = forge.get_datastore(config)
fs = forge.get_filestore(config)
sq = NamedQueue('dispatch-submission-queue', host=config.core.redis.persistent.host,
                port=config.core.redis.persistent.port, db=config.core.redis.persistent.db)
submission = None

def purge_submit():
    wipe_users(ds)
    wipe_submissions(ds, fs)

    sq.delete()


@pytest.fixture(scope="module")
def datastore(request):
    global submission
    create_users(ds)
    submission = create_submission(ds, fs)
    request.addfinalizer(purge_submit)
    return ds


# noinspection PyUnusedLocal
def test_resubmit(datastore, login_session):
    _, session = login_session

    sq.delete()
    submission_files = [f.sha256 for f in submission.files]
    resp = get_api_data(session, f"{HOST}/api/v4/submit/resubmit/{submission.sid}/")
    assert resp['params']['description'].startswith('Resubmit')
    assert resp['sid'] != submission.sid
    for f in resp['files']:
        assert f['sha256'] in submission_files

    msg = SubmissionTask(sq.pop(blocking=False))
    assert msg.submission.sid == resp['sid']


# noinspection PyUnusedLocal
def test_resubmit_dynamic(datastore, login_session):
    _, session = login_session

    sq.delete()
    sha256 = random.choice(submission.results)[:64]
    resp = get_api_data(session, f"{HOST}/api/v4/submit/dynamic/{sha256}/")
    assert resp['params']['description'].startswith('Resubmit')
    assert resp['params']['description'].endswith('Dynamic Analysis')
    assert resp['sid'] != submission.sid
    for f in resp['files']:
        assert f['sha256'] == sha256
    assert resp['params']['services']['resubmit'] == ['Dynamic Analysis']

    msg = SubmissionTask(sq.pop(blocking=False))
    assert msg.submission.sid == resp['sid']


# noinspection PyUnusedLocal
def test_submit_hash(datastore, login_session):
    _, session = login_session

    sq.delete()
    data = {
        'sha256': random.choice(submission.results)[:64],
        'name': 'random_hash.txt',
        'metadata': {'test': 'test_submit_hash'}
    }
    resp = get_api_data(session, f"{HOST}/api/v4/submit/", method="POST", data=json.dumps(data))
    assert isinstance(resp['sid'], str)
    for f in resp['files']:
        assert f['sha256'] == data['sha256']
        assert f['name'] == data['name']

    msg = SubmissionTask(sq.pop(blocking=False))
    assert msg.submission.sid == resp['sid']


# noinspection PyUnusedLocal
def test_submit_url(datastore, login_session):
    _, session = login_session

    sq.delete()
    data = {
        'url': 'https://www.cyber.gc.ca/en/theme-gcwu-fegc/assets/wmms.svg',
        'name': 'wmms.svg',
        'metadata': {'test': 'test_submit_url'}
    }
    resp = get_api_data(session, f"{HOST}/api/v4/submit/", method="POST", data=json.dumps(data))
    assert isinstance(resp['sid'], str)
    for f in resp['files']:
        assert f['name'] == data['name']

    msg = SubmissionTask(sq.pop(blocking=False))
    assert msg.submission.sid == resp['sid']


# noinspection PyUnusedLocal
def test_submit_binary(datastore, login_session):
    _, session = login_session

    sq.delete()
    byte_str = get_random_phrase(wmin=15, wmax=30).encode()
    sha256 = hashlib.sha256(byte_str).hexdigest()
    data = {
        'binary': base64.b64encode(byte_str).decode(),
        'name': 'text.txt',
        'metadata': {'test': 'test_submit_binary'}
    }
    resp = get_api_data(session, f"{HOST}/api/v4/submit/", method="POST", data=json.dumps(data))
    assert isinstance(resp['sid'], str)
    for f in resp['files']:
        assert f['sha256'] == sha256
        assert f['name'] == data['name']

    msg = SubmissionTask(sq.pop(blocking=False))
    assert msg.submission.sid == resp['sid']
