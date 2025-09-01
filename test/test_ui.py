import hashlib
import json
import random
from io import BytesIO

import pytest
from conftest import APIError, get_api_data

from assemblyline.common.uid import get_random_id
from assemblyline.odm.random_data import (
    create_services,
    create_users,
    wipe_services,
    wipe_users,
)
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


def upload_file_flowjs(session, host):
    total_chunk = random.randint(2, 5)

    data = get_random_phrase(wmin=50, wmax=100)
    if len(data) % total_chunk != 0:
        data = data[: -(len(data) % total_chunk)]

    chunk_size = int(len(data) / total_chunk)
    ui_id = get_random_id()

    chunk_size = int(len(data) / total_chunk)
    ui_id = get_random_id()

    counter = 0
    while True:
        x = counter % total_chunk
        try:
            params = {
                "flowChunkNumber": f"{x + 1}",
                "flowChunkSize": f"{chunk_size}",
                "flowTotalSize": f"{chunk_size*total_chunk}",
                "flowFilename": "test.txt",
                "flowTotalChunks": f"{total_chunk}",
                "flowIdentifier": ui_id,
                "flowCurrentChunkSize": f"{chunk_size}",
            }
            resp = get_api_data(session, f"{host}/api/v4/ui/flowjs/", params=params)
            if resp["exist"]:
                counter += 1
        except APIError as e:
            if (
                str(e) == "Chunk does not exist, please send it!"
                or str(e).startswith("204: ")
                or str(e).startswith("206: ")
            ):
                params = {
                    "flowChunkNumber": f"{x + 1}",
                    "flowChunkSize": f"{chunk_size}",
                    "flowCurrentChunkSize": f"{chunk_size}",
                    "flowTotalSize": f"{chunk_size*total_chunk}",
                    "flowIdentifier": ui_id,
                    "flowFilename": "test.txt",
                    "flowRelativePath": "/tmp/test/test.txt",
                    "flowTotalChunks": f"{total_chunk}",
                }
                bio = BytesIO(data[x * chunk_size : (x * chunk_size) + chunk_size].encode())
                resp = get_api_data(
                    session, f"{host}/api/v4/ui/flowjs/", method="POST", data=params, headers={}, files={"file": bio}
                )
                assert resp["success"]
                if resp["completed"]:
                    break
            else:
                raise

    return ui_id, data


# noinspection PyUnusedLocal
def test_ui_submission(datastore, login_session):
    _, session, host = login_session

    ui_id, data = upload_file_flowjs(session, host)

    ui_params = get_api_data(session, f"{host}/api/v4/user/settings/admin/")['submission_profiles']['static']
    ui_params['filename'] = 'test.txt'
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


def test_ui_submission_parameter(datastore, login_session):
    _, session, host = login_session

    ui_id, data = upload_file_flowjs(session, host)

    submission_parameter = get_api_data(session, f"{host}/api/v4/user/settings/admin/")["submission_profiles"]["static"]
    submission_parameter["filename"] = "test.txt"
    # test UI submitted password for Extract are stored in submission correctly
    extract_spec = {
        "name": "Extract",
        "params": [{"default": "", "hide": False, "name": "password", "type": "str", "value": "test"}],
    }
    submission_parameter["ui_params"] = {"service_spec": [extract_spec]}

    resp = get_api_data(
        session, f"{host}/api/v4/ui/start/{ui_id}/", method="POST", data=json.dumps(submission_parameter)
    )
    datastore.submission.commit()
    submission = datastore.submission.get(resp["sid"])
    submission_params = submission["params"]

    assert "Extract" in submission_params["service_spec"]
    assert "password" in submission_params["service_spec"]["Extract"]
    assert "password" in submission_params["service_spec"]["Extract"]
    assert submission_params["service_spec"]["Extract"]["password"] == "test"

    # Empty string does NOT get stored in the submission because the value of default and value are the same
    ui_id, data = upload_file_flowjs(session, host)
    empty_string_extract_spec = {
        "name": "Extract",
        "params": [{"default": "", "hide": False, "name": "password", "type": "str", "value": ""}],
    }
    submission_parameter["ui_params"] = {"service_spec": [empty_string_extract_spec]}

    resp = get_api_data(
        session, f"{host}/api/v4/ui/start/{ui_id}/", method="POST", data=json.dumps(submission_parameter)
    )
    datastore.submission.commit()
    submission = datastore.submission.get(resp["sid"])
    submission_params = submission["params"]

    assert "Extract" not in submission_params["service_spec"]

    # test if UI param initial_data is stored in submission properly
    submission_parameter["ui_params"] = {"initial_data": json.dumps({"password": ["test"]})}

    ui_id, data = upload_file_flowjs(session, host)
    resp = get_api_data(
        session, f"{host}/api/v4/ui/start/{ui_id}/", method="POST", data=json.dumps(submission_parameter)
    )
    datastore.submission.commit()
    submission = datastore.submission.get(resp["sid"])
    submission_params = submission["params"]

    assert submission_params["initial_data"] == json.dumps({"password": ["test"]})

    # if initial_data contains empty string password in the list, it will get passed on to the submission
    submission_parameter["ui_params"] = {"initial_data": json.dumps({"password": [""]})}

    ui_id, data = upload_file_flowjs(session, host)
    resp = get_api_data(
        session, f"{host}/api/v4/ui/start/{ui_id}/", method="POST", data=json.dumps(submission_parameter)
    )
    datastore.submission.commit()
    submission = datastore.submission.get(resp["sid"])
    submission_params = submission["params"]

    assert submission_params["initial_data"] == json.dumps({"password": [""]})
