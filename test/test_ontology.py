import json
import pytest

from conftest import get_api_data

from assemblyline.odm.models.alert import Alert
from assemblyline.odm.randomizer import random_model_obj
from assemblyline.odm.random_data import create_users, wipe_users, create_submission, wipe_submissions, wipe_alerts


test_alert = None
test_submission = None


def cleanup(ds, fs):
    wipe_users(ds)
    wipe_submissions(ds, fs)
    wipe_alerts(ds)


@pytest.fixture(scope="module")
def datastore(request, datastore_connection, filestore):
    global test_alert, test_submission
    ds = datastore_connection

    create_users(ds)
    test_submission = create_submission(ds, filestore)

    test_alert = random_model_obj(Alert)
    test_alert.sid = test_submission.sid
    test_alert.file.sha256 = test_submission.files[0].sha256
    ds.alert.save(test_alert.alert_id, test_alert)
    ds.alert.commit()

    request.addfinalizer(lambda: cleanup(ds, filestore))
    return ds


def test_get_ontology_for_alert(datastore, login_session):
    _, session, host = login_session

    data = get_api_data(session, f"{host}/api/v4/ontology/alert/{test_alert.alert_id}/", raw=True)
    res = [json.loads(line) for line in data.splitlines()]
    assert len(res) != 0
    assert any([record['file']['sha256'] == test_alert.file.sha256 for record in res])


def test_get_ontology_for_file(datastore, login_session):
    _, session, host = login_session

    data = get_api_data(session, f"{host}/api/v4/ontology/file/{test_alert.file.sha256}/", raw=True)
    res = [json.loads(line) for line in data.splitlines()]
    assert len(res) != 0
    assert all([record['file']['sha256'] == test_alert.file.sha256 for record in res])


def test_get_ontology_for_submission(datastore, login_session):
    _, session, host = login_session

    data = get_api_data(session, f"{host}/api/v4/ontology/submission/{test_submission.sid}/", raw=True)
    res = [json.loads(line) for line in data.splitlines()]
    assert len(res) != 0
    assert any([record['file']['sha256'] == test_submission.files[0].sha256 for record in res])
