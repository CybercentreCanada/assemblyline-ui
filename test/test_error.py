
import pytest

from assemblyline.odm.models.error import Error
from assemblyline.odm.models.file import File
from assemblyline.odm.models.service import Service
from assemblyline.odm.randomizer import random_model_obj, random_minimal_obj
from assemblyline.odm.random_data import create_users, wipe_users, create_services, wipe_services

from conftest import get_api_data, APIError

NUM_ERRORS = 10
test_error = None


@pytest.fixture(scope="module")
def datastore(datastore_connection):
    try:
        global test_error

        create_users(datastore_connection)
        create_services(datastore_connection)

        for _ in range(NUM_ERRORS):
            e = random_model_obj(Error)
            if test_error is None:
                test_error = e

            f = random_model_obj(File)
            f.sha256 = e.sha256
            datastore_connection.file.save(f.sha256, f)
            datastore_connection.error.save(e.build_key(), e)

        datastore_connection.file.commit()
        datastore_connection.error.commit()
        yield datastore_connection
    finally:
        wipe_users(datastore_connection)
        wipe_services(datastore_connection)
        datastore_connection.error.wipe()
        datastore_connection.file.wipe()


def test_get_error(datastore, login_session):
    _, session, host = login_session

    resp = get_api_data(session, f"{host}/api/v4/error/{test_error.build_key()}/")
    err = Error(resp)
    assert err == test_error


def test_list_error(datastore, login_session):
    _, session, host = login_session

    resp = get_api_data(session, f"{host}/api/v4/error/list/")
    assert resp['total'] == NUM_ERRORS


def test_get_error_file_classification_denied(datastore, login_user_session):
    """Verify that a user with TLP:CLEAR classification cannot access an error
    associated with a file classified at TLP:A+S//CMR."""
    _, session, host = login_user_session

    f = random_model_obj(File)
    f.classification = "TLP:A+S//CMR"
    datastore.file.save(f.sha256, f)

    e = random_model_obj(Error)
    e.sha256 = f.sha256
    e_key = e.build_key()
    datastore.error.save(e_key, e)

    datastore.file.commit()
    datastore.error.commit()

    try:
        with pytest.raises(APIError, match="not found"):
            get_api_data(session, f"{host}/api/v4/error/{e_key}/")
    finally:
        datastore.error.delete(e_key)
        datastore.file.delete(f.sha256)
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
    e.response.service_name = "ClassifiedTestSvc"
    e.response.service_version = "1.0.0"
    e_key = e.build_key()
    datastore.error.save(e_key, e)

    service = random_minimal_obj(Service, as_json=True)
    service['name'] = "ClassifiedTestSvc"
    service['enabled'] = True
    service['classification'] = "TLP:A+S//CMR"
    datastore.service.save(f"{service['name']}_{service['version']}", service)
    datastore.service_delta.save(service['name'], {"version": service["version"]})

    datastore.file.commit()
    datastore.error.commit()
    datastore.service.commit()
    datastore.service_delta.commit()

    try:
        with pytest.raises(APIError, match="not found"):
            get_api_data(session, f"{host}/api/v4/error/{e_key}/")
    finally:
        datastore.error.delete(e_key)
        datastore.file.delete(f.sha256)
        datastore.service.delete(f"{service['name']}_{service['version']}")
        datastore.service_delta.delete(service['name'])
        datastore.error.commit()
        datastore.file.commit()
        datastore.service.commit()
        datastore.service_delta.commit()
