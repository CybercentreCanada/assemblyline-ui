import pytest

# noinspection PyUnresolvedReferences
from base import HOST, login_session, get_api_data, create_users, wipe_users, create_services, wipe_services

from assemblyline.common import forge

ds = forge.get_datastore()


def purge_submission():
    wipe_users(ds)


@pytest.fixture(scope="module")
def datastore(request):
    create_users(ds)
    request.addfinalizer(purge_submission)
    return ds


# noinspection PyUnusedLocal
def test_delete_submission(datastore, login_session):
    _, session = login_session

    sid = 1
    resp = get_api_data(session, f"{HOST}/api/v4/submission/{sid}/", method="DELETE")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_get_submission_file_result(datastore, login_session):
    _, session = login_session

    sid = sha256 = 1
    resp = get_api_data(session, f"{HOST}/api/v4/submission/{sid}/file/{sha256}/")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_get_submission(datastore, login_session):
    _, session = login_session

    sid = 1
    resp = get_api_data(session, f"{HOST}/api/v4/submission/{sid}/")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_get_submission_is_completed(datastore, login_session):
    _, session = login_session

    sid = 1
    resp = get_api_data(session, f"{HOST}/api/v4/submission/is_completed/{sid}/")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_get_submission_full(datastore, login_session):
    _, session = login_session

    sid = 1
    resp = get_api_data(session, f"{HOST}/api/v4/submission/full/{sid}/")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_get_submission_summary(datastore, login_session):
    _, session = login_session

    sid = 1
    resp = get_api_data(session, f"{HOST}/api/v4/submission/summary/{sid}/")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_get_submission_tree(datastore, login_session):
    _, session = login_session

    sid = 1
    resp = get_api_data(session, f"{HOST}/api/v4/submission/tree/{sid}/")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_get_submission_list_group(datastore, login_session):
    _, session = login_session

    sid = 1
    resp = get_api_data(session, f"{HOST}/api/v4/submission/list/group/{sid}/")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_get_submission_list_user(datastore, login_session):
    _, session = login_session

    sid = 1
    resp = get_api_data(session, f"{HOST}/api/v4/submission/list/user/{sid}/")
    assert isinstance(resp, dict)
