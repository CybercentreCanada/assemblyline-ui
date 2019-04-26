import json

import pytest

from assemblyline.common import forge
from assemblyline.odm.models.alert import Alert
from assemblyline.odm.randomizer import random_model_obj
# noinspection PyUnresolvedReferences
from base import HOST, login_session, get_api_data, create_users, wipe_users

alert_id = None
ds = forge.get_datastore()


def purge_alert():
    wipe_users(ds)
    ds.alert.wipe()


@pytest.fixture(scope="module")
def datastore(request):
    global alert_id

    create_users(ds)

    for _ in range(10):
        a = random_model_obj(Alert)
        if alert_id is None:
            alert_id = a.alert_id
        a.owner = None
        ds.alert.save(a.alert_id, a)
    ds.alert.commit()

    request.addfinalizer(purge_alert)
    return ds

# noinspection PyUnusedLocal
def test_get_labels(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/alert/labels/")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_get_priorities(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/alert/priorities/")
    assert "CRITICAL" in resp or "HIGH" in resp or "LOW" in resp or "MEDIUM" in resp


# noinspection PyUnusedLocal
def test_get_statistics(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/alert/statistics/")
    assert "file.md5" in resp


# noinspection PyUnusedLocal
def test_get_statuses(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/alert/statuses/")
    assert "ASSESS" in resp or "MALICIOUS" in resp or "NON_MALICIOUS" in resp or "TRIAGE" in resp


# noinspection PyUnusedLocal
def test_related(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/alert/related/", params={'q': "id:*"})
    assert isinstance(resp, list)


# noinspection PyUnusedLocal
def test_get_alert_id(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/alert/{alert_id}/")
    try:
        resp = Alert(resp)
    except (ValueError, TypeError):
        pytest.fail("Invalid alert")
    assert isinstance(resp, Alert)


# noinspection PyUnusedLocal
def test_list(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/alert/list/")
    assert 'items' in resp and 'total' in resp


# noinspection PyUnusedLocal
def test_grouped_alert(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/alert/grouped/file.sha256/")
    assert 'counted_total' in resp


# noinspection PyUnusedLocal
def test_ownership(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/alert/ownership/{alert_id}/")
    assert resp.get('success', False)

    datastore.alert.commit()

    resp = get_api_data(session, f"{HOST}/api/v4/alert/ownership/batch/", params={'q': "id:*"})
    assert resp.get('success', 0) > 0


# noinspection PyUnusedLocal
def test_labeling(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/alert/label/{alert_id}/",
                        data=json.dumps(['TEST1', 'TEST2']), method='POST')
    assert resp.get('success', False)

    datastore.alert.commit()

    resp = get_api_data(session, f"{HOST}/api/v4/alert/label/batch/", data=json.dumps(['BATCH1', 'BATCH2']),
                        params={'q': "id:*"}, method='POST')
    assert resp.get('success', 0) > 0


# noinspection PyUnusedLocal
def test_priorities(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/alert/priority/{alert_id}/", data=json.dumps("HIGH"), method='POST')
    assert resp.get('success', False)

    datastore.alert.commit()

    resp = get_api_data(session, f"{HOST}/api/v4/alert/priority/batch/", data=json.dumps("LOW"),
                        params={'q': "id:*"}, method='POST')
    assert resp.get('success', 0) > 0


# noinspection PyUnusedLocal
def test_statuses(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/alert/status/{alert_id}/", data=json.dumps("ASSESS"), method='POST')
    assert resp.get('success', False)

    datastore.alert.commit()

    resp = get_api_data(session, f"{HOST}/api/v4/alert/status/batch/", data=json.dumps("MALICIOUS"),
                        params={'q': "id:*"}, method='POST')
    assert resp.get('success', 0) > 0
