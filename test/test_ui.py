import pytest
import requests
import warnings

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


def purge_system():
    from assemblyline.common import forge
    ds = forge.get_datastore()
    
    ds.user.delete_matching("id:*")
    ds.user_settings.delete_matching("id:*")
    ds.service.delete_matching("id:*")
    ds.service_delta.delete_matching("id:*")
    ds.signature.delete_matching("id:*")
    ds.heuristic.delete_matching("id:*")
    ds.alert.delete_matching("id:*")


@pytest.fixture(scope="module")
def data_for_test(request):
    from assemblyline.common import forge
    ds = forge.get_datastore()

    user_total  = ds.user.search("id:*", rows=0)['total']
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


def get_api_data(session, url, params=None, body=None, method="GET"):
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')

        if method == "GET":
            res = session.get(url, params=params, verify=False)
        elif method == "POST":
            res = session.post(url, body=body, params=params, verify=False)
        elif method == "DELETE":
            res = session.delete(url, params=params, verify=False)
        elif method == "PUT":
            res = session.put(url, body=body, params=params, verify=False)
        else:
            raise InvalidRequestMethod(method)

        if "XSRF-TOKEN" in res.cookies:
            session.headers.update({"X-XSRF-TOKEN": res.cookies['XSRF-TOKEN']})

        res_data = res.json()

        if res.ok:
            return res_data['api_response']
        else:
            raise APIError(res_data["api_error_message"])


def test_data_validity(data_for_test):
    assert data_for_test.user.search("id:*", rows=0)['total'] == 2
    assert data_for_test.service_delta.search("id:*", rows=0)['total'] == 14
    assert data_for_test.signature.search("id:*", rows=0)['total'] == 19
    assert data_for_test.heuristic.search("id:*", rows=0)['total'] > 0


# noinspection PyUnusedLocal
def test_login(data_for_test, login_session):
    user_info, session = login_session
    assert user_info['username'] == "admin"

    resp = get_api_data(session, f"{HOST}/api/")
    assert isinstance(resp, list)

    resp = get_api_data(session, f"{HOST}/api/v4/auth/logout/")
    assert resp.get('success', False) == True


# noinspection PyUnusedLocal
def test_api_keys(data_for_test, login_session):
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
    assert resp.get('success', False) == True

    # Delete the read/write key
    resp = get_api_data(session, f"{HOST}/api/v4/auth/apikey/{key_name}_rw/", method="DELETE")
    assert resp.get('success', False) == True

    # Delete the write key
    resp = get_api_data(session, f"{HOST}/api/v4/auth/apikey/{key_name}_w/", method="DELETE")
    assert resp.get('success', False) == True


# noinspection PyUnusedLocal
def test_otp(data_for_test, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/auth/setup_otp/")
    secret_key = resp.get('secret_key', None)
    assert secret_key is not None

    resp = get_api_data(session, f"{HOST}/api/v4/auth/validate_otp/{get_totp_token(secret_key)}/")
    assert resp.get('success', False) == True

    resp = get_api_data(session, f"{HOST}/api/v4/auth/disable_otp/")
    assert resp.get('success', False) == True


# noinspection PyUnusedLocal
def test_doc(data_for_test, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/")
    assert 'apis' in resp and 'blueprints' in resp


# noinspection PyUnusedLocal
def test_help(data_for_test, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/help/classification_definition/")
    assert isinstance(resp, dict)

    resp = get_api_data(session, f"{HOST}/api/v4/help/configuration/")
    assert isinstance(resp, dict)

    resp = get_api_data(session, f"{HOST}/api/v4/help/constants/")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_alert(data_for_test, login_session):
    _, session = login_session

    alert_id = "123"

    resp = get_api_data(session, f"{HOST}/api/v4/alert/labels/")
    assert isinstance(resp, dict)

    resp = get_api_data(session, f"{HOST}/api/v4/alert/priorities/")
    assert "CRITICAL" in resp or "HIGH" in resp or "LOW" in resp or "MEDIUM" in resp

    resp = get_api_data(session, f"{HOST}/api/v4/alert/statistics/")
    assert "file.md5" in resp

    resp = get_api_data(session, f"{HOST}/api/v4/alert/statuses/")
    assert "ASSESS" in resp or "MALICIOUS" in resp or "NON_MALICIOUS" in resp or "TRIAGE" in resp

    resp = get_api_data(session, f"{HOST}/api/v4/alert/related/", params={'q': "id:*"})
    assert isinstance(resp, list)

    alert_id = resp[0]

    resp = get_api_data(session, f"{HOST}/api/v4/alert/{alert_id}/")
    try:
        resp = Alert(resp)
    except (ValueError, TypeError):
        pytest.fail("Invalid alert")
    assert isinstance(resp, Alert)

    resp = get_api_data(session, f"{HOST}/api/v4/alert/list/")
    assert 'items' in resp and 'total' in resp

    resp = get_api_data(session, f"{HOST}/api/v4/alert/grouped/file.sha256/")
    assert 'counted_total' in resp

    resp = get_api_data(session, f"{HOST}/api/v4/alert/ownership/{alert_id}/")
    assert resp.get('success', False)

    resp = get_api_data(session, f"{HOST}/api/v4/alert/ownership/batch/", params={'q': "id:*"})
    assert resp.get('success', 0) > 0

    resp = get_api_data(session, f"{HOST}/api/v4/alert/label/{alert_id}/", method='POST')
    resp = get_api_data(session, f"{HOST}/api/v4/alert/label/batch/", params={'q': "id:*"}, method='POST')

    resp = get_api_data(session, f"{HOST}/api/v4/alert/priority/{alert_id}/", method='POST')
    resp = get_api_data(session, f"{HOST}/api/v4/alert/priority/batch/", params={'q': "id:*"}, method='POST')

    resp = get_api_data(session, f"{HOST}/api/v4/alert/status/{alert_id}/", method='POST')
    resp = get_api_data(session, f"{HOST}/api/v4/alert/status/batch/", params={'q': "id:*"}, method='POST')


# noinspection PyUnusedLocal
def test_bundle(data_for_test, login_session):
    _, session = login_session

    # TODO: bundle tests


# noinspection PyUnusedLocal
def test_error(data_for_test, login_session):
    _, session = login_session

    # TODO: Error tests


# noinspection PyUnusedLocal
def test_file(data_for_test, login_session):
    _, session = login_session

    # TODO: File tests


# noinspection PyUnusedLocal
def test_hash_search(data_for_test, login_session):
    _, session = login_session

    # TODO: Hash_search tests


# noinspection PyUnusedLocal
def test_ingest(data_for_test, login_session):
    _, session = login_session

    # TODO: ingest tests


# noinspection PyUnusedLocal
def test_live(data_for_test, login_session):
    _, session = login_session

    # TODO: live tests


# noinspection PyUnusedLocal
def test_result(data_for_test, login_session):
    _, session = login_session

    # TODO: Result tests


# noinspection PyUnusedLocal
def test_search(data_for_test, login_session):
    _, session = login_session

    # TODO: Search tests


# noinspection PyUnusedLocal
def test_service(data_for_test, login_session):
    _, session = login_session

    # TODO: Service tests


# noinspection PyUnusedLocal
def test_signature(data_for_test, login_session):
    _, session = login_session

    # TODO: Signature tests


# noinspection PyUnusedLocal
def test_submission(data_for_test, login_session):
    _, session = login_session

    # TODO: Submission tests


# noinspection PyUnusedLocal
def test_submit(data_for_test, login_session):
    _, session = login_session

    # TODO: Submit tests


# noinspection PyUnusedLocal
def test_tc_signature(data_for_test, login_session):
    _, session = login_session

    # TODO: TC Signature tests


# noinspection PyUnusedLocal
def test_user(data_for_test, login_session):
    _, session = login_session

    # TODO: User tests


# noinspection PyUnusedLocal
def test_vm(data_for_test, login_session):
    _, session = login_session

    # TODO: VM tests


# noinspection PyUnusedLocal
def test_workflow(data_for_test, login_session):
    _, session = login_session

    # TODO: workflow tests
