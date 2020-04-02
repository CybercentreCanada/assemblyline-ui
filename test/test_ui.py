import hashlib
import json
import pytest
import random

from conftest import APIError, get_api_data
from io import BytesIO

from assemblyline.odm.random_data import create_users, wipe_users, create_services, wipe_services
from assemblyline.common.uid import get_random_id
from assemblyline.odm.randomizer import get_random_phrase


@pytest.fixture(scope="module")
def datastore(datastore_connection):
    try:
        create_users(datastore_connection)
        create_services(datastore_connection)
        yield datastore_connection
    finally:
        wipe_users(datastore_connection)
        wipe_services(datastore_connection)


# noinspection PyUnusedLocal
def test_ui_submission(datastore, login_session):
    _, session, host = login_session

    total_chunk = random.randint(2, 5)

    data = get_random_phrase(wmin=50, wmax=100)
    if len(data) % total_chunk != 0:
        data = data[:-(len(data) % total_chunk)]

    chunk_size = int(len(data)/total_chunk)
    ui_id = get_random_id()

    counter = 0
    while True:
        x = counter % total_chunk
        try:
            params = {
                'flowChunkNumber': f'{x + 1}',
                'flowChunkSize': f'{chunk_size}',
                'flowTotalSize': f'{chunk_size*total_chunk}',
                'flowFilename': 'test.txt',
                'flowTotalChunks': f'{total_chunk}',
                'flowIdentifier': ui_id,
                'flowCurrentChunkSize': f'{chunk_size}'
            }
            resp = get_api_data(session, f"{host}/api/v4/ui/flowjs/", params=params)
            if resp['exist']:
                counter += 1
        except APIError as e:
            if str(e) == "Chunk does not exist, please send it!":
                params = {
                    'flowChunkNumber': f'{x + 1}',
                    'flowChunkSize': f'{chunk_size}',
                    'flowCurrentChunkSize': f'{chunk_size}',
                    'flowTotalSize': f'{chunk_size*total_chunk}',
                    'flowIdentifier': ui_id,
                    'flowFilename': 'test.txt',
                    'flowRelativePath': '/tmp/test/test.txt',
                    'flowTotalChunks': f'{total_chunk}',
                }
                bio = BytesIO(data[x*chunk_size:(x*chunk_size)+chunk_size].encode())
                resp = get_api_data(session, f"{host}/api/v4/ui/flowjs/", method="POST", data=params, headers={},
                                    files={'file': bio})
                assert resp['success']
                if resp['completed']:
                    break
            else:
                raise

    ui_params = get_api_data(session, f"{host}/api/v4/user/settings/admin/")
    resp = get_api_data(session, f"{host}/api/v4/ui/start/{ui_id}/", method="POST", data=json.dumps(ui_params))
    assert resp['started']

    datastore.submission.commit()
    submission = datastore.submission.get(resp['sid'])
    assert submission is not None
    assert submission.files[0].size == len(data)
    assert submission.files[0].sha256 == hashlib.sha256(data.encode()).hexdigest()
    assert submission.files[0].name == 'test.txt'
    assert submission.sid == resp['sid']
    assert submission.state == 'submitted'
