import json

import pytest
import requests
import warnings

from assemblyline.common import forge
from assemblyline.common.security import get_password_hash, get_totp_token
from assemblyline.common.yara import YaraImporter
from assemblyline.odm.models.alert import Alert
from assemblyline.odm.models.heuristic import Heuristic
from assemblyline.odm.models.service import Service
from assemblyline.odm.models.user import User
from assemblyline.odm.models.user_settings import UserSettings
from assemblyline.odm.randomizer import SERVICES, random_model_obj, get_random_phrase, get_random_hash


class SetupException(Exception):
    pass


class InvalidRequestMethod(Exception):
    pass


class APIError(Exception):
    pass


class CrashLogger(object):
    def info(self, _):
        pass

    def warn(self, msg):
        raise SetupException(msg)

    def error(self, msg):
        raise SetupException(msg)


HOST = "https://localhost:443"
alert_id = None
ds = forge.get_datastore()


def purge_system():
    ds.user.wipe()
    ds.user_settings.wipe()
    ds.service.wipe()
    ds.service_delta.wipe()
    ds.signature.wipe()
    ds.heuristic.wipe()
    ds.alert.wipe()


@pytest.fixture(scope="module")
def datastore(request):
    global alert_id
    purge_system()

    user_total = ds.user.search("id:*", rows=0)['total']
    if user_total == 0:
        user_data = User({
            "agrees_with_tos": "NOW",
            "classification": "RESTRICTED",
            "name": "Admin user",
            "password": get_password_hash("admin"),
            "uname": "admin",
            "is_admin": True})
        ds.user.save('admin', user_data)
        ds.user_settings.save('admin', UserSettings())
        user_data = User({"name": "user", "password": get_password_hash("user"), "uname": "user"})
        ds.user.save('user', user_data)
        ds.user_settings.save('user', UserSettings())
        ds.user.commit()

    service_total = ds.service_delta.search("id:*", rows=0)['total']
    if service_total == 0:
        for svc_name, svc in SERVICES.items():
            service_data = Service({
                "name": svc_name,
                "enabled": True,
                "category": svc[0],
                "stage": svc[1],
                "version": "3.3.0"
            })
            # Save a v3 service
            ds.service.save(f"{service_data.name}_{service_data.version}", service_data)

            # Save the same service as v4
            service_data.version = "4.0.0"
            ds.service.save(f"{service_data.name}_{service_data.version}", service_data)

            # Save the default delta entry
            ds.service_delta.save(service_data.name, {"version": service_data.version})
        ds.service_delta.commit()
        ds.service.commit()

    signature_total = ds.signature.search("id:*", rows=0)['total']
    if signature_total == 0:
        yp = YaraImporter(logger=CrashLogger())
        parsed = yp.parse_file('al_yara_signatures.yar')
        yp.import_now([p['rule'] for p in parsed])
        ds.signature.commit()

    heur_total = ds.heuristic.search("id:*", rows=0)['total']
    if heur_total == 0:
        for _ in range(40):
            h = random_model_obj(Heuristic)
            h.name = get_random_phrase()
            ds.heuristic.save(h.heur_id, h)
        ds.heuristic.commit()

    alert_total = ds.alert.search("id:*", rows=0)['total']
    if alert_total == 0:
        for _ in range(10):
            a = random_model_obj(Alert)
            if alert_id is None:
                alert_id = a.alert_id
            a.owner = None
            ds.alert.save(a.alert_id, a)
        ds.alert.commit()

    request.addfinalizer(purge_system)

    return ds


@pytest.fixture(scope='function')
def login_session():
    session = requests.Session()
    data = get_api_data(session, f"{HOST}/api/v4/auth/login/", params={'user': 'admin', 'password': 'admin'})
    return data, session


def get_api_data(session, url, params=None, data=None, method="GET"):
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')

        if method == "GET":
            res = session.get(url, params=params, verify=False)
        elif method == "POST":
            res = session.post(url, data=data, params=params, verify=False,
                               headers={'content-type': 'application/json'})
        elif method == "DELETE":
            res = session.delete(url, params=params, verify=False)
        elif method == "PUT":
            res = session.put(url, data=data, params=params, verify=False,
                              headers={'content-type': 'application/json'})
        else:
            raise InvalidRequestMethod(method)

        if "XSRF-TOKEN" in res.cookies:
            session.headers.update({"X-XSRF-TOKEN": res.cookies['XSRF-TOKEN']})

        res_data = res.json()

        if res.ok:
            return res_data['api_response']
        else:
            raise APIError(res_data["api_error_message"])


def test_data_validity(datastore):
    assert datastore.user.search("id:*", rows=0)['total'] == 2
    assert datastore.service_delta.search("id:*", rows=0)['total'] == 14
    assert datastore.signature.search("id:*", rows=0)['total'] == 19
    assert datastore.heuristic.search("id:*", rows=0)['total'] > 0
    assert datastore.alert.search("id:*", rows=0)['total'] == 10


# noinspection PyUnusedLocal
def test_login(datastore, login_session):
    user_info, session = login_session
    assert user_info['username'] == "admin"

    resp = get_api_data(session, f"{HOST}/api/")
    assert isinstance(resp, list)

    resp = get_api_data(session, f"{HOST}/api/v4/auth/logout/")
    assert resp.get('success', False) is True


# noinspection PyUnusedLocal
def test_api_keys(datastore, login_session):
    _, session = login_session
    key_name = get_random_hash(6)

    # Added a read apikey
    resp = get_api_data(session, f"{HOST}/api/v4/auth/apikey/{key_name}_r/READ/")
    read_pass = resp.get('apikey', None)
    assert read_pass is not None

    # Cannot reuse apikey names
    with pytest.raises(APIError):
        resp = get_api_data(session, f"{HOST}/api/v4/auth/apikey/{key_name}_r/READ_WRITE/")

    # Added a read/write key
    resp = get_api_data(session, f"{HOST}/api/v4/auth/apikey/{key_name}_rw/READ_WRITE/")
    read_write_pass = resp.get('apikey', None)
    assert read_write_pass is not None

    # Added a write key
    resp = get_api_data(session, f"{HOST}/api/v4/auth/apikey/{key_name}_w/WRITE/")
    write_pass = resp.get('apikey', None)
    assert write_pass is not None

    # Try to login with the read key
    resp = get_api_data(session, f"{HOST}/api/v4/auth/login/",
                        params={'user': 'admin', 'apikey': read_pass})
    assert resp.get('privileges', []) == ['R']

    # Try to login with the read/write key
    resp = get_api_data(session, f"{HOST}/api/v4/auth/login/",
                        params={'user': 'admin', 'apikey': read_write_pass})
    assert resp.get('privileges', []) == ["R", "W"]

    # Try to login with the write key
    resp = get_api_data(session, f"{HOST}/api/v4/auth/login/",
                        params={'user': 'admin', 'apikey': write_pass})
    assert resp.get('privileges', []) == ["W"]

    # Login with username and password so we are allowed to delete apikeys
    get_api_data(session, f"{HOST}/api/v4/auth/login/", params={'user': 'admin', 'password': 'admin'})

    # Delete the read key
    resp = get_api_data(session, f"{HOST}/api/v4/auth/apikey/{key_name}_r/", method="DELETE")
    assert resp.get('success', False) is True

    # Delete the read/write key
    resp = get_api_data(session, f"{HOST}/api/v4/auth/apikey/{key_name}_rw/", method="DELETE")
    assert resp.get('success', False) is True

    # Delete the write key
    resp = get_api_data(session, f"{HOST}/api/v4/auth/apikey/{key_name}_w/", method="DELETE")
    assert resp.get('success', False) is True


# noinspection PyUnusedLocal
def test_otp(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/auth/setup_otp/")
    secret_key = resp.get('secret_key', None)
    assert secret_key is not None

    resp = get_api_data(session, f"{HOST}/api/v4/auth/validate_otp/{get_totp_token(secret_key)}/")
    assert resp.get('success', False) is True

    resp = get_api_data(session, f"{HOST}/api/v4/auth/disable_otp/")
    assert resp.get('success', False) is True


# noinspection PyUnusedLocal
def test_doc(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/")
    assert 'apis' in resp and 'blueprints' in resp


# noinspection PyUnusedLocal
def test_help(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/help/classification_definition/")
    assert isinstance(resp, dict)

    resp = get_api_data(session, f"{HOST}/api/v4/help/configuration/")
    assert isinstance(resp, dict)

    resp = get_api_data(session, f"{HOST}/api/v4/help/constants/")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_alert_get_labels(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/alert/labels/")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_alert_get_priorities(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/alert/priorities/")
    assert "CRITICAL" in resp or "HIGH" in resp or "LOW" in resp or "MEDIUM" in resp


# noinspection PyUnusedLocal
def test_alert_get_statistics(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/alert/statistics/")
    assert "file.md5" in resp


# noinspection PyUnusedLocal
def test_alert_get_statuses(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/alert/statuses/")
    assert "ASSESS" in resp or "MALICIOUS" in resp or "NON_MALICIOUS" in resp or "TRIAGE" in resp


# noinspection PyUnusedLocal
def test_alert_related(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/alert/related/", params={'q': "id:*"})
    assert isinstance(resp, list)


# noinspection PyUnusedLocal
def test_alert_get_alert_id(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/alert/{alert_id}/")
    try:
        resp = Alert(resp)
    except (ValueError, TypeError):
        pytest.fail("Invalid alert")
    assert isinstance(resp, Alert)


# noinspection PyUnusedLocal
def test_alert_list(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/alert/list/")
    assert 'items' in resp and 'total' in resp


# noinspection PyUnusedLocal
def test_alert_grouped_alert(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/alert/grouped/file.sha256/")
    assert 'counted_total' in resp


# noinspection PyUnusedLocal
def test_alert_ownership(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/alert/ownership/{alert_id}/")
    assert resp.get('success', False)

    datastore.alert.commit()

    resp = get_api_data(session, f"{HOST}/api/v4/alert/ownership/batch/", params={'q': "id:*"})
    assert resp.get('success', 0) > 0


# noinspection PyUnusedLocal
def test_alert_labeling(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/alert/label/{alert_id}/",
                        data=json.dumps(['TEST1', 'TEST2']), method='POST')
    assert resp.get('success', False)

    datastore.alert.commit()

    resp = get_api_data(session, f"{HOST}/api/v4/alert/label/batch/", data=json.dumps(['BATCH1', 'BATCH2']),
                        params={'q': "id:*"}, method='POST')
    assert resp.get('success', 0) > 0


# noinspection PyUnusedLocal
def test_alert_priorities(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/alert/priority/{alert_id}/", data=json.dumps("HIGH"), method='POST')
    assert resp.get('success', False)

    datastore.alert.commit()

    resp = get_api_data(session, f"{HOST}/api/v4/alert/priority/batch/", data=json.dumps("LOW"),
                        params={'q': "id:*"}, method='POST')
    assert resp.get('success', 0) > 0


# noinspection PyUnusedLocal
def test_alert_statuses(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/alert/status/{alert_id}/", data=json.dumps("ASSESS"), method='POST')
    assert resp.get('success', False)

    datastore.alert.commit()

    resp = get_api_data(session, f"{HOST}/api/v4/alert/status/batch/", data=json.dumps("MALICIOUS"),
                        params={'q': "id:*"}, method='POST')
    assert resp.get('success', 0) > 0


# noinspection PyUnusedLocal
def test_bundle(datastore, login_session):
    _, session = login_session

    # TODO: bundle tests


# noinspection PyUnusedLocal
def test_error(datastore, login_session):
    _, session = login_session

    # TODO: Error tests


# noinspection PyUnusedLocal
def test_file(datastore, login_session):
    _, session = login_session

    # TODO: File tests


# noinspection PyUnusedLocal
def test_hash_search(datastore, login_session):
    _, session = login_session

    # TODO: Hash_search tests


# noinspection PyUnusedLocal
def test_ingest(datastore, login_session):
    _, session = login_session

    # TODO: ingest tests


# noinspection PyUnusedLocal
def test_live(datastore, login_session):
    _, session = login_session

    # TODO: live tests


# noinspection PyUnusedLocal
def test_result(datastore, login_session):
    _, session = login_session

    # TODO: Result tests


# noinspection PyUnusedLocal
def test_search(datastore, login_session):
    _, session = login_session

    # TODO: Search tests


# noinspection PyUnusedLocal
def test_service(datastore, login_session):
    _, session = login_session

    # TODO: Service tests


# noinspection PyUnusedLocal
def test_signature(datastore, login_session):
    _, session = login_session

    # TODO: Signature tests


# noinspection PyUnusedLocal
def test_submission(datastore, login_session):
    _, session = login_session

    # TODO: Submission tests


# noinspection PyUnusedLocal
def test_submit(datastore, login_session):
    _, session = login_session

    # TODO: Submit tests


# noinspection PyUnusedLocal
def test_tc_signature(datastore, login_session):
    _, session = login_session

    # TODO: TC Signature tests


# noinspection PyUnusedLocal
def test_user(datastore, login_session):
    _, session = login_session

    # TODO: User tests


# noinspection PyUnusedLocal
def test_vm(datastore, login_session):
    _, session = login_session

    # TODO: VM tests


# noinspection PyUnusedLocal
def test_workflow(datastore, login_session):
    _, session = login_session

    # TODO: workflow tests
