import json
import pytest
import random

from conftest import get_api_data, APIError

from assemblyline.odm.models.error import Error
from assemblyline.odm.models.file import File
from assemblyline.odm.models.result import Result
from assemblyline.odm.models.service import Service
from assemblyline.odm.randomizer import random_model_obj, random_minimal_obj
from assemblyline.odm.random_data import create_users, wipe_users, create_services, wipe_services

TEST_RESULTS = 10
file_list = []
error_key_list = []
result_key_list = []


@pytest.fixture(scope="module")
def datastore(datastore_connection):
    ds = datastore_connection
    try:
        create_users(ds)
        create_services(ds)

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
        wipe_services(ds)


def test_get_result(datastore, login_session):
    _, session, host = login_session

    result_key = random.choice(result_key_list)
    sha256, service, version, _ = result_key.split('.')
    resp = get_api_data(session, f"{host}/api/v4/result/{result_key}/")
    assert resp['sha256'] == sha256 \
        and resp['response']['service_name'] == service \
        and resp['response']['service_version'] == version[1:].replace("_", ".")


def test_get_result_error(datastore, login_session):
    _, session, host = login_session

    error_key = random.choice(error_key_list)
    sha256, service, version, _, _ = error_key.split('.')
    resp = get_api_data(session, f"{host}/api/v4/result/error/{error_key}/")
    assert resp['sha256'] == sha256 \
        and resp['response']['service_name'] == service \
        and resp['response']['service_version'] == version[1:].replace("_", ".")


def test_get_multiple_keys(datastore, login_session):
    _, session, host = login_session

    data = {
        'error': error_key_list,
        'result': result_key_list
    }

    resp = get_api_data(session, f"{host}/api/v4/result/multiple_keys/", method="POST", data=json.dumps(data))
    assert sorted(list(resp['error'].keys())) == sorted(error_key_list) \
        and sorted(list(resp['result'].keys())) == sorted(result_key_list)


def test_get_error_classification_check(datastore, login_session):
    """Verify that an admin user (high classification) can still access errors normally."""
    _, session, host = login_session

    error_key = random.choice(error_key_list)
    sha256, service, version, _, _ = error_key.split('.')
    resp = get_api_data(session, f"{host}/api/v4/result/error/{error_key}/")
    assert resp['sha256'] == sha256 \
        and resp['response']['service_name'] == service \
        and resp['response']['service_version'] == version[1:].replace("_", ".")


def test_get_error_classification_denied(datastore, login_user_session):
    """Verify that a user with TLP:CLEAR classification cannot access an error
    associated with a file classified at TLP:AMBER+STRICT."""
    _, session, host = login_user_session

    # Create a file with high classification
    f = random_model_obj(File)
    f.classification = "TLP:A+S//CMR"
    datastore.file.save(f.sha256, f)
    datastore.file.commit()

    # Create an error linked to that file
    e = random_model_obj(Error)
    e.sha256 = f.sha256
    e_key = e.build_key()
    datastore.error.save(e_key, e)
    datastore.error.commit()

    try:
        with pytest.raises(APIError, match="does not exists"):
            get_api_data(session, f"{host}/api/v4/result/error/{e_key}/")
    finally:
        # Clean up the dedicated test data
        datastore.error.delete(e_key)
        datastore.file.delete(f.sha256)
        datastore.error.commit()
        datastore.file.commit()


def test_get_multiple_errors_classification_filtered(datastore, login_user_session):
    """Verify that errors associated with high-classification files are filtered
    out from the multiple_keys response for a low-classification user."""
    _, session, host = login_user_session

    # Create a low-classification file and error (should be visible to user)
    f_low = random_model_obj(File)
    f_low.classification = "TLP:C"
    datastore.file.save(f_low.sha256, f_low)

    e_low = random_model_obj(Error)
    e_low.sha256 = f_low.sha256
    e_low_key = e_low.build_key()
    datastore.error.save(e_low_key, e_low)

    # Create a high-classification file and error (should be filtered out)
    f_high = random_model_obj(File)
    f_high.classification = "TLP:A+S//CMR"
    datastore.file.save(f_high.sha256, f_high)

    e_high = random_model_obj(Error)
    e_high.sha256 = f_high.sha256
    e_high_key = e_high.build_key()
    datastore.error.save(e_high_key, e_high)

    datastore.file.commit()
    datastore.error.commit()

    try:
        data = {
            'error': [e_low_key, e_high_key],
            'result': []
        }
        resp = get_api_data(session, f"{host}/api/v4/result/multiple_keys/", method="POST",
                            data=json.dumps(data))

        # The low-classification error should be present
        assert e_low_key in resp['error']
        # The high-classification error should be filtered out
        assert e_high_key not in resp['error']
    finally:
        # Clean up the dedicated test data
        datastore.error.delete(e_low_key)
        datastore.error.delete(e_high_key)
        datastore.file.delete(f_low.sha256)
        datastore.file.delete(f_high.sha256)
        datastore.error.commit()
        datastore.file.commit()


def test_get_error_service_classification_denied(datastore, login_user_session):
    """Verify that a user with TLP:CLEAR classification cannot access an error
    from a service classified at TLP:A+S//CMR, even if the file itself is TLP:C."""
    _, session, host = login_user_session

    f = random_model_obj(File)
    f.classification = "TLP:C"
    datastore.file.save(f.sha256, f)

    e = random_model_obj(Error)
    e.sha256 = f.sha256
    e.response.service_name = "ClassifiedSvc"
    e.response.service_version = "1.0.0"
    e_key = e.build_key()
    datastore.error.save(e_key, e)

    service = random_minimal_obj(Service, as_json=True)
    service['name'] = "ClassifiedSvc"
    service['enabled'] = True
    service['classification'] = "TLP:A+S//CMR"
    datastore.service.save(f"{service['name']}_{service['version']}", service)
    datastore.service_delta.save(service['name'], {"version": service["version"]})

    datastore.file.commit()
    datastore.error.commit()
    datastore.service.commit()
    datastore.service_delta.commit()

    try:
        with pytest.raises(APIError, match="does not exists"):
            get_api_data(session, f"{host}/api/v4/result/error/{e_key}/")
    finally:
        datastore.error.delete(e_key)
        datastore.file.delete(f.sha256)
        datastore.service.delete(f"{service['name']}_{service['version']}")
        datastore.service_delta.delete(service['name'])
        datastore.error.commit()
        datastore.file.commit()
        datastore.service.commit()
        datastore.service_delta.commit()


def test_get_multiple_errors_service_classification_filtered(datastore, login_user_session):
    """Verify that errors from high-classification services are filtered
    out from the multiple_keys response for a low-classification user."""
    _, session, host = login_user_session

    # Create a low-classification file for both errors
    f = random_model_obj(File)
    f.classification = "TLP:C"
    datastore.file.save(f.sha256, f)

    # Error from a service the user can see
    e_visible = random_model_obj(Error)
    e_visible.sha256 = f.sha256
    e_visible.response.service_name = "VisibleSvc"
    e_visible.response.service_version = "1.0.0"
    e_visible_key = e_visible.build_key()
    datastore.error.save(e_visible_key, e_visible)

    svc_visible = random_minimal_obj(Service, as_json=True)
    svc_visible['name'] = "VisibleSvc"
    svc_visible['enabled'] = True
    svc_visible['classification'] = "TLP:C"
    datastore.service.save(f"{svc_visible['name']}_{svc_visible['version']}", svc_visible)
    datastore.service_delta.save(svc_visible['name'], {"version": svc_visible["version"]})

    # Error from a service the user cannot see
    e_hidden = random_model_obj(Error)
    e_hidden.sha256 = f.sha256
    e_hidden.response.service_name = "HiddenSvc"
    e_hidden.response.service_version = "1.0.0"
    e_hidden_key = e_hidden.build_key()
    datastore.error.save(e_hidden_key, e_hidden)

    svc_hidden = random_minimal_obj(Service, as_json=True)
    svc_hidden['name'] = "HiddenSvc"
    svc_hidden['enabled'] = True
    svc_hidden['classification'] = "TLP:A+S//CMR"
    datastore.service.save(f"{svc_hidden['name']}_{svc_hidden['version']}", svc_hidden)
    datastore.service_delta.save(svc_hidden['name'], {"version": svc_hidden["version"]})

    datastore.file.commit()
    datastore.error.commit()
    datastore.service.commit()
    datastore.service_delta.commit()

    try:
        data = {
            'error': [e_visible_key, e_hidden_key],
            'result': []
        }
        resp = get_api_data(session, f"{host}/api/v4/result/multiple_keys/", method="POST",
                            data=json.dumps(data))

        assert e_visible_key in resp['error']
        assert e_hidden_key not in resp['error']
    finally:
        datastore.error.delete(e_visible_key)
        datastore.error.delete(e_hidden_key)
        datastore.file.delete(f.sha256)
        datastore.service.delete(f"{svc_visible['name']}_{svc_visible['version']}")
        datastore.service_delta.delete(svc_visible['name'])
        datastore.service.delete(f"{svc_hidden['name']}_{svc_hidden['version']}")
        datastore.service_delta.delete(svc_hidden['name'])
        datastore.error.commit()
        datastore.file.commit()
        datastore.service.commit()
        datastore.service_delta.commit()
