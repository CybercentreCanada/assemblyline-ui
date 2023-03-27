import pytest

from conftest import get_api_data
from assemblyline.odm.random_data import create_users, wipe_users
from assemblyline_ui.api.v4 import federated_lookup
from assemblyline_ui.app import app


@pytest.fixture()
def test_client():
    """generate a test client."""
    with app.test_client() as client:
        with app.app_context():
            yield client


@pytest.fixture()
def local_login_session(test_client):
    data = get_api_data(test_client, "/api/v4/auth/login/", params={'user': 'admin', 'password': 'admin'})
    return data, test_client


@pytest.fixture(scope="module")
def datastore(datastore_connection):
    try:
        create_users(datastore_connection)
        yield datastore_connection
    finally:
        wipe_users(datastore_connection)


def test_lookup_valid(datastore, login_session):
    _, session, host = login_session

    resp = get_api_data(session, f"{host}/api/v4/federated_lookup/ioc/")
    assert resp == ["TODO"]


# def test_lookup_hash_mb(datastore, login_session, mocker):
def test_lookup_hash_mb(datastore, local_login_session, mocker):
    digest = "7de2c1bf58bce09eecc70476747d88a26163c3d6bb1d85235c24a558d1f16755"
    # digest = "7de2c1bf58bce09eecc70476747d88a26163c3d6bb1d85235c24a558d1f16754"

    mock_response = mocker.MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "query_status": "ok",
        "data": [{
            "sha256_hash": digest,
        }],
    }

    mock_session = mocker.patch.object(federated_lookup, "Session", autospec=True)
    # mock_session = mocker.patch("assemblyline_ui.api.v4.federated_lookup.Session", autospec=True)
    mock_session_obj = mock_session()
    mock_get = mock_session_obj.get
    mock_get.return_value = mock_response

    # _, session, host = login_session
    # rsp = get_api_data(
    #    session,
    #    f"{host}/api/v4/federated_lookup/ioc/hash/{digest}/",
    #    params={"sources": "malware_bazaar"}
    # )

    _, client = local_login_session
    rsp = get_api_data(
        client,
        f"/api/v4/federated_lookup/ioc/hash/{digest}/",
        params={"sources": "malware_bazaar"}
    )

    print(f"{rsp=}")

    mock_response.assert_called_once()
    assert rsp['sha256'] == 'asdf'
# {
#        "api_error_message": "",
#        "api_response": {
#            digest: {
#                "classification": "UNRESTRICTED",
#                "link": f"https://bazaar.abuse.ch/sample/{digest}/",
#            },
#        },
#        "api_status_code": 200,
#    }
