import pytest

# noinspection PyUnresolvedReferences
from base import HOST, login_session, get_api_data, create_users, wipe_users, create_services, wipe_services

from assemblyline.common import forge

ds = forge.get_datastore()


def purge_user():
    wipe_users(ds)


@pytest.fixture(scope="module")
def datastore(request):
    create_users(ds)
    request.addfinalizer(purge_user)
    return ds



# noinspection PyUnusedLocal
def test_add_favorite(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/user/favorite/{username}/{fav_type}/", method="PUT")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_add_user(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/user/{username}/", method="PUT")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_agree_to_tos(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/user/tos/{username}/")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_get_user(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/user/{username}/")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_get_user_avatar(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/user/avatar/{username}/")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_get_user_favorites(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/user/favorites/{username}/")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_get_user_settings(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/user/settings/{username}/")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_get_user_submission_params(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/user/submission_params/{username}/")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_list_users(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/user/list/")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_remove_user(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/user/{username}/", method="DELETE")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_remove_user_favorite(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/user/favorites/{username}/{fav_type}/", method="DELETE")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_set_user(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/user/{username}/", method="POST")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_set_user_avatar(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/user/avatar/{username}/", method="POST")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_set_user_favorites(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/user/favorites/{username}/", method="POST")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_set_user_settings(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/user/settings/{username}/", method="POST")
    assert isinstance(resp, dict)
