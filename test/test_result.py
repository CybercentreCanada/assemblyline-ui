import json
import pytest
import random

from conftest import HOST, get_api_data

from assemblyline.odm.models.error import Error
from assemblyline.odm.models.file import File
from assemblyline.odm.models.result import Result
from assemblyline.odm.randomizer import random_model_obj
from assemblyline.odm.random_data import create_users, wipe_users

TEST_RESULTS = 10
file_list = []
error_key_list = []
result_key_list = []


@pytest.fixture(scope="module")
def datastore(datastore_connection):
    ds = datastore_connection
    try:
        create_users(ds)

        for x in range(TEST_RESULTS):
            f = random_model_obj(File)
            ds.file.save(f.sha256, f)
            file_list.append(f.sha256)
        ds.file.commit()

        for x in range(TEST_RESULTS):
            e = random_model_obj(Error)
            e.sha256 = file_list[x]
            ds.error.save(e.build_key(), e)
            error_key_list.append(e.build_key())
        ds.error.commit()

        for x in range(TEST_RESULTS):
            r = random_model_obj(Result)
            r.sha256 = file_list[x]
            ds.result.save(r.build_key(), r)
            result_key_list.append(r.build_key())
        ds.result.commit()
        yield ds
    finally:
        ds.error.wipe()
        ds.file.wipe()
        ds.result.wipe()
        wipe_users(ds)


# noinspection PyUnusedLocal
def test_get_result(datastore, login_session):
    _, session = login_session

    result_key = random.choice(result_key_list)
    sha256, service, version, _ = result_key.split('.')
    resp = get_api_data(session, f"{HOST}/api/v4/result/{result_key}/")
    assert resp['sha256'] == sha256 \
        and resp['response']['service_name'] == service \
        and resp['response']['service_version'] == version[1:].replace("_", ".")


# noinspection PyUnusedLocal
def test_get_result_error(datastore, login_session):
    _, session = login_session

    error_key = random.choice(error_key_list)
    sha256, service, version, _, _ = error_key.split('.')
    resp = get_api_data(session, f"{HOST}/api/v4/result/error/{error_key}/")
    assert resp['sha256'] == sha256 \
        and resp['response']['service_name'] == service \
        and resp['response']['service_version'] == version[1:].replace("_", ".")


# noinspection PyUnusedLocal
def test_get_multiple_keys(datastore, login_session):
    _, session = login_session

    data = {
        'error': error_key_list,
        'result': result_key_list
    }

    resp = get_api_data(session, f"{HOST}/api/v4/result/multiple_keys/", method="POST", data=json.dumps(data))
    assert sorted(list(resp['error'].keys())) == sorted(error_key_list) \
        and sorted(list(resp['result'].keys())) == sorted(result_key_list)
