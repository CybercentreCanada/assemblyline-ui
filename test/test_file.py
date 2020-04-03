import random

import pytest

from assemblyline.common import forge
from assemblyline.common.dict_utils import unflatten
from assemblyline.common.tagging import tag_list_to_dict
from assemblyline.odm.models.file import File
from assemblyline.odm.models.result import Result
from assemblyline.odm.randomizer import random_model_obj
from assemblyline.odm.random_data import create_users, wipe_users

from conftest import get_api_data
from cart import unpack_stream
from io import BytesIO

NUM_FILES = 10
test_file = None
file_res_list = []


@pytest.fixture(scope="module")
def datastore(datastore_connection, filestore):
    global test_file, file_res_list
    ds = datastore_connection
    try:
        create_users(ds)
        for _f in range(NUM_FILES):
            f = random_model_obj(File)
            if test_file is None:
                test_file = f
            ds.file.save(f.sha256, f)

            filestore.put(f.sha256, f.sha256)

            for _r in range(random.randint(1, 3)):
                r = random_model_obj(Result)
                r.sha256 = f.sha256
                file_res_list.append(r.build_key())
                ds.result.save(r.build_key(), r)

        ds.file.commit()
        ds.result.commit()
        yield ds
    finally:
        wipe_users(ds)
        ds.file.wipe()
        ds.result.wipe()
        for key in file_res_list:
            filestore.delete(key[:64])


# noinspection PyUnusedLocal
def test_download_cart(datastore, login_session):
    _, session, host = login_session

    rand_hash = random.choice(file_res_list)[:64]
    resp = get_api_data(session, f"{host}/api/v4/file/download/{rand_hash}/?encoding=cart", raw=True)
    assert resp.startswith(b'CART')

    out = BytesIO()
    unpack_stream(BytesIO(resp), out)
    out.flush()
    out.seek(0)
    dl_hash = out.read().decode()
    assert dl_hash == rand_hash


# noinspection PyUnusedLocal
def test_download_raw(datastore, login_session):
    _, session, host = login_session

    rand_hash = random.choice(file_res_list)[:64]
    resp = get_api_data(session, f"{host}/api/v4/file/download/{rand_hash}/?encoding=raw", raw=True)
    assert resp.decode() == rand_hash


# noinspection PyUnusedLocal
def test_ascii(datastore, login_session):
    _, session, host = login_session

    rand_hash = random.choice(file_res_list)[:64]
    resp = get_api_data(session, f"{host}/api/v4/file/ascii/{rand_hash}/")
    assert resp == rand_hash


# noinspection PyUnusedLocal
def test_children(datastore, login_session):
    _, session, host = login_session

    rand_hash = random.choice(file_res_list)[:64]
    resp = get_api_data(session, f"{host}/api/v4/file/children/{rand_hash}/")

    for child in resp:
        assert 'name' in child and 'sha256' in child and len(child) == 2


# noinspection PyUnusedLocal
def test_hex(datastore, login_session):
    _, session, host = login_session

    rand_hash = random.choice(file_res_list)[:64]
    resp = get_api_data(session, f"{host}/api/v4/file/hex/{rand_hash}/")
    assert resp.startswith("00000000:") and len(resp) == 311


# noinspection PyUnusedLocal
def test_info(datastore, login_session):
    _, session, host = login_session

    resp = get_api_data(session, f"{host}/api/v4/file/info/{test_file.sha256}/")
    get_file = File(resp)
    assert test_file == get_file


# noinspection PyUnusedLocal
def test_result(datastore, login_session):
    _, session, host = login_session

    rand_hash = random.choice(file_res_list)[:64]
    resp = get_api_data(session, f"{host}/api/v4/file/result/{rand_hash}/")
    assert 'childrens' in resp and 'file_info' in resp and 'results' in resp and 'tags' in resp


# noinspection PyUnusedLocal
def test_result_for_service(datastore, login_session):
    _, session, host = login_session

    rand_key = random.choice(file_res_list)
    rand_hash = rand_key[:64]
    service_name = rand_key.split('.')[1]
    resp = get_api_data(session, f"{host}/api/v4/file/result/{rand_hash}/{service_name}/")
    result_dict = resp['results'][0]
    for s in result_dict['result']['sections']:
        s['tags'] = unflatten(tag_list_to_dict(s['tags']))
    res_data = Result(result_dict)
    assert res_data.build_key() in file_res_list


# noinspection PyUnusedLocal
def test_score(datastore, login_session):
    _, session, host = login_session

    rand_key = random.choice(file_res_list)
    rand_hash = rand_key[:64]
    resp = get_api_data(session, f"{host}/api/v4/file/score/{rand_hash}/")
    assert resp['score'] > 0
    assert rand_hash in resp['file_info']['sha256']
    for k in resp['result_keys']:
        assert k.startswith(rand_hash)


# noinspection PyUnusedLocal
def test_strings(datastore, login_session):
    _, session, host = login_session

    rand_hash = random.choice(file_res_list)[:64]
    resp = get_api_data(session, f"{host}/api/v4/file/strings/{rand_hash}/")
    assert resp == rand_hash
