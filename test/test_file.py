import hashlib
import random
import zipfile
from base64 import b64decode
from io import BytesIO

import pytest
from assemblyline.common.dict_utils import unflatten
from assemblyline.common.tagging import tag_list_to_dict
from assemblyline.odm.models.file import File
from assemblyline.odm.models.result import Result
from assemblyline.odm.random_data import create_users, wipe_users
from assemblyline.odm.randomizer import random_model_obj
from cart import unpack_stream
from conftest import APIError, get_api_data

NUM_FILES = 10
test_file = None
file_res_list = []
file_list = []


@pytest.fixture(scope="module")
def datastore(datastore_connection, filestore):
    global test_file, file_res_list, file_list
    ds = datastore_connection
    try:
        create_users(ds)
        # noinspection PyUnusedLocal
        for _f in range(NUM_FILES):
            f = random_model_obj(File)
            if test_file is None:
                test_file = f
                test_file.from_archive = False
            file_list.append(f.as_primitives())
            ds.file.save(f.sha256, f)

            filestore.put(f.sha256, f.sha256)

            # noinspection PyUnusedLocal
            for _r in range(random.randint(1, 3)):
                r = random_model_obj(Result)
                r.sha256 = f.sha256
                file_res_list.append(r.build_key())
                ds.result.save(r.build_key(), r)

        # Add an image file for testing file_image_datastream
        for from_archive in [True, False]:
            f = random_model_obj(File)
            f.from_archive = from_archive
            f.type = 'image/png'
            f.is_section_image = True
            file_list.append(f.as_primitives())
            ds.file.save(f.sha256, f)
            filestore.put(f.sha256, f.sha256)

        ds.file.commit()
        ds.result.commit()
        yield ds
    finally:
        wipe_users(ds)
        ds.file.wipe()
        ds.result.wipe()
        for key in file_res_list:
            filestore.delete(key[:64])


@pytest.mark.parametrize("from_archive", [True, False])
def test_download_cart(datastore, login_session, from_archive):
    _, session, host = login_session

    rand_hash = random.choice([file for file in file_list if file['from_archive'] == from_archive])['sha256']
    resp = get_api_data(session, f"{host}/api/v4/file/download/{rand_hash}/?encoding=cart", raw=True)
    assert resp.startswith(b'CART')

    out = BytesIO()
    unpack_stream(BytesIO(resp), out)
    out.flush()
    out.seek(0)
    dl_hash = out.read().decode()
    assert dl_hash == rand_hash


@pytest.mark.parametrize("from_archive", [True, False])
def test_download_raw(datastore, login_session, from_archive):
    _, session, host = login_session

    rand_hash = random.choice([file for file in file_list if file['from_archive'] == from_archive])['sha256']
    resp = get_api_data(session, f"{host}/api/v4/file/download/{rand_hash}/?encoding=raw", raw=True)
    assert resp.decode() == rand_hash


@pytest.mark.parametrize("from_archive", [True, False])
def test_download_zip(datastore, login_session, from_archive):
    _, session, host = login_session

    rand_hash = random.choice([file for file in file_list if file['from_archive'] == from_archive])['sha256']
    resp = get_api_data(session, f"{host}/api/v4/file/download/{rand_hash}/?encoding=zip&password=infected", raw=True)
    with zipfile.ZipFile(BytesIO(resp)) as zf:
        assert zf.namelist() == [rand_hash]
        assert zf.read(rand_hash, pwd=b'infected').decode() == rand_hash


@pytest.mark.parametrize("name", ["@list", "-@", "-TT evil", "-i@list"])
def test_download_zip_argv_injection(datastore, filestore, login_session, name):
    """A hostile `name` must not influence the archive contents — the
    user-supplied name is only ever used for Content-Disposition, never
    for on-disk paths or zip(1) argv.
    The file content `b'/etc/passwd\n'` is the payload of the original
    exploit: the attack worked because the downloaded bytes get written
    to download_path and then zip is tricked into re-reading that file
    as an include-list.
    """
    _, session, host = login_session

    payload = b'/etc/passwd\n'
    sha256 = hashlib.sha256(payload).hexdigest()
    f = random_model_obj(File)
    f.from_archive = False
    f.sha256 = sha256
    datastore.file.save(sha256, f)
    filestore.put(sha256, payload)

    resp = get_api_data(
        session,
        f"{host}/api/v4/file/download/{sha256}/",
        params={"encoding": "zip", "password": "infected", "name": name},
        raw=True,
    )
    with zipfile.ZipFile(BytesIO(resp)) as zf:
        names = zf.namelist()
        assert names == [sha256], f"unexpected archive members: {names}"
        assert zf.read(sha256, pwd=b'infected') == b'/etc/passwd\n'


@pytest.mark.parametrize("password", ["", "   ", "a" * 129, "bad\npass", "bad\x00pass"])
def test_download_zip_invalid_password(datastore, login_session, password):
    _, session, host = login_session

    rand_hash = random.choice(file_list)['sha256']
    with pytest.raises(APIError):
        get_api_data(
            session,
            f"{host}/api/v4/file/download/{rand_hash}/",
            params={"encoding": "zip", "password": password},
        )


@pytest.mark.parametrize("from_archive", [True, False])
def test_ascii(datastore, login_session, from_archive):
    _, session, host = login_session

    rand_hash = random.choice([file for file in file_list if file['from_archive'] == from_archive])['sha256']
    resp = get_api_data(session, f"{host}/api/v4/file/ascii/{rand_hash}/")
    assert resp == {"content": rand_hash, "truncated": False}


def test_children(datastore, login_session):
    _, session, host = login_session

    rand_hash = random.choice(file_res_list)[:64]
    resp = get_api_data(session, f"{host}/api/v4/file/children/{rand_hash}/")

    for child in resp:
        assert 'name' in child and 'sha256' in child and len(child) == 2


@pytest.mark.parametrize("from_archive", [True, False])
def test_file_image_datastream(datastore, login_session, from_archive):
    _, session, host = login_session

    rand_hash = random.choice([file for file in file_list if file['from_archive'] ==
                              from_archive and file['type'].startswith('image')])['sha256']
    resp = get_api_data(session, f"{host}/api/v4/file/image/{rand_hash}/")
    assert b64decode(resp.replace('data:image/png;base64,', '')).decode() == rand_hash


@pytest.mark.parametrize("from_archive", [True, False])
def test_hex(datastore, login_session, from_archive):
    _, session, host = login_session

    rand_hash = random.choice([file for file in file_list if file['from_archive'] == from_archive])['sha256']
    resp = get_api_data(session, f"{host}/api/v4/file/hex/{rand_hash}/")
    assert resp["content"].startswith("00000000:") and len(resp["content"]) == 311


def test_info(datastore, login_session):
    _, session, host = login_session

    resp = get_api_data(session, f"{host}/api/v4/file/info/{test_file.sha256}/")
    get_file = File(resp)
    assert test_file == get_file


def test_result(datastore, login_session):
    _, session, host = login_session

    rand_hash = random.choice(file_res_list)[:64]
    resp = get_api_data(session, f"{host}/api/v4/file/result/{rand_hash}/")
    assert 'childrens' in resp and 'file_info' in resp and 'results' in resp and 'tags' in resp


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


def test_score(datastore, login_session):
    _, session, host = login_session

    rand_key = random.choice(file_res_list)
    rand_hash = rand_key[:64]
    resp = get_api_data(session, f"{host}/api/v4/file/score/{rand_hash}/")
    assert resp['score'] > 0
    assert rand_hash in resp['file_info']['sha256']
    for k in resp['result_keys']:
        assert k.startswith(rand_hash)


@pytest.mark.parametrize("from_archive", [True, False])
def test_strings(datastore, login_session, from_archive):
    _, session, host = login_session

    rand_hash = random.choice([file for file in file_list if file['from_archive'] == from_archive])['sha256']
    resp = get_api_data(session, f"{host}/api/v4/file/strings/{rand_hash}/")
    assert resp == {"content": rand_hash, "truncated": False}
