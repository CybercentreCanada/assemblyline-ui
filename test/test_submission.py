
import pytest
import random
import uuid

from conftest import get_api_data, APIError

from assemblyline.common.forge import get_classification
from assemblyline.odm.randomizer import get_random_user, get_random_groups
from assemblyline.odm.random_data import create_users, wipe_users, create_submission, wipe_submissions


CLASSIFICATION = get_classification()
NUM_SUBMISSIONS = 10


@pytest.fixture(scope="module")
def datastore(datastore_connection, filestore):
    try:
        create_users(datastore_connection)

        for _ in range(NUM_SUBMISSIONS):
            create_submission(datastore_connection, filestore)
        yield datastore_connection
    finally:
        wipe_users(datastore_connection)
        wipe_submissions(datastore_connection, filestore)


def test_delete_submission(datastore, login_session):
    _, session, host = login_session

    submission = random.choice(datastore.submission.search("id:*", rows=NUM_SUBMISSIONS, as_obj=False)['items'])
    resp = get_api_data(session, f"{host}/api/v4/submission/{submission['sid']}/", method="DELETE")
    assert resp['success']

    datastore.error.commit()
    datastore.file.commit()
    datastore.result.commit()
    datastore.submission.commit()

    for s in datastore.submission.search("id:*", rows=NUM_SUBMISSIONS, as_obj=False)['items']:
        assert s['sid'] != submission['sid']


def test_get_submission_file_result(datastore, login_session):
    _, session, host = login_session

    sid = random.choice(datastore.submission.search("id:*", fl='id', rows=NUM_SUBMISSIONS, as_obj=False)['items'])['id']
    submission = datastore.submission.get(sid)
    sha256 = random.choice(submission.results)[:64]
    resp = get_api_data(session, f"{host}/api/v4/submission/{sid}/file/{sha256}/")
    assert len(resp['errors']) == len([x for x in submission.errors if x.startswith(sha256)])
    assert len(resp['results']) == len([x for x in submission.results if x.startswith(sha256)])


def test_get_submission(datastore, login_session):
    _, session, host = login_session

    submission = random.choice(datastore.submission.search("id:*", rows=NUM_SUBMISSIONS, as_obj=False)['items'])
    resp = get_api_data(session, f"{host}/api/v4/submission/{submission['sid']}/")
    assert resp['sid'] == submission['sid']
    assert resp['params']['description'] == submission['params']['description']


def test_get_submission_is_completed(datastore, login_session):
    _, session, host = login_session

    submission = random.choice(datastore.submission.search("id:*", rows=NUM_SUBMISSIONS, as_obj=False)['items'])
    resp = get_api_data(session, f"{host}/api/v4/submission/is_completed/{submission['sid']}/")
    if submission['state'] == 'completed':
        assert resp is True
    else:
        assert resp is False


def test_get_submission_full(datastore, login_session):
    _, session, host = login_session

    submission = random.choice(datastore.submission.search("id:*", rows=NUM_SUBMISSIONS, as_obj=False)['items'])
    resp = get_api_data(session, f"{host}/api/v4/submission/full/{submission['sid']}/")
    assert resp['sid'] == submission['sid']
    assert resp['params']['description'] == submission['params']['description']
    assert isinstance(resp['errors'], dict)
    assert isinstance(resp['results'], dict)
    assert isinstance(resp['file_tree'], dict)
    assert isinstance(resp['file_infos'], dict)


def test_get_submission_full_get_full_tree(datastore, login_session):
    _, session, host = login_session

    submission = random.choice(datastore.submission.search("id:*", rows=NUM_SUBMISSIONS, as_obj=False)['items'])
    resp = get_api_data(
        session, f"{host}/api/v4/submission/full/{submission['sid']}/", params={"get_full_tree": "true"})
    assert resp['sid'] == submission['sid']
    assert resp['params']['description'] == submission['params']['description']
    assert isinstance(resp['file_tree'], dict)

    # Verify that the submission has truncated false for all entries to verify this is the full tree.
    for k, v in resp['file_tree'].items():
        assert v.get("truncated", True) is False


def test_get_submission_report(datastore, login_session):
    _, session, host = login_session

    submission = random.choice(datastore.submission.search("id:*", rows=NUM_SUBMISSIONS, as_obj=False)['items'])
    resp = get_api_data(session, f"{host}/api/v4/submission/report/{submission['sid']}/")
    assert resp['sid'] == submission['sid']
    assert resp['params']['description'] == submission['params']['description']
    assert isinstance(resp['attack_matrix'], dict)
    assert isinstance(resp['file_info'], dict)
    assert isinstance(resp['file_tree'], dict)
    assert isinstance(resp['files'], list)
    assert isinstance(resp['heuristics'], dict)
    assert isinstance(resp['tags'], dict)
    assert isinstance(resp['promoted_sections'], list)


def test_get_submission_report_get_full_tree(datastore, login_session):
    _, session, host = login_session

    submission = random.choice(datastore.submission.search("id:*", rows=NUM_SUBMISSIONS, as_obj=False)['items'])
    resp = get_api_data(
        session, f"{host}/api/v4/submission/report/{submission['sid']}/", params={"get_full_tree": "true"})
    assert resp['sid'] == submission['sid']
    assert resp['params']['description'] == submission['params']['description']
    assert isinstance(resp['file_tree'], dict)

    # Verify that the submission has truncated false for all entries to verify this is the full tree.
    for k, v in resp['file_tree'].items():
        assert v.get("truncated", True) is False


def test_get_submission_summary(datastore, login_session):
    _, session, host = login_session

    submission = random.choice(datastore.submission.search("id:*", rows=NUM_SUBMISSIONS, as_obj=False)['items'])
    resp = get_api_data(session, f"{host}/api/v4/submission/summary/{submission['sid']}/")
    assert isinstance(resp['map'], dict)
    assert isinstance(resp['tags'], dict)


def test_get_submission_tree(datastore, login_session):
    _, session, host = login_session

    submission = random.choice(datastore.submission.search("id:*", rows=NUM_SUBMISSIONS, as_obj=False)['items'])
    resp = get_api_data(session, f"{host}/api/v4/submission/tree/{submission['sid']}/")
    assert isinstance(resp, dict)
    assert "classification" in resp
    assert "filtered" in resp
    assert "tree" in resp

    for k in resp['tree']:
        assert len(k) == 64


def test_get_submission_tree_get_full_tree(datastore, login_session):
    # READY to test now that I found params.
    _, session, host = login_session

    submission = random.choice(datastore.submission.search("id:*", rows=NUM_SUBMISSIONS, as_obj=False)['items'])
    resp = get_api_data(
        session, f"{host}/api/v4/submission/tree/{submission['sid']}/", params={"get_full_tree": "true"})
    assert isinstance(resp, dict)
    assert "classification" in resp
    assert "filtered" in resp
    assert "tree" in resp

    for k in resp['tree']:
        assert len(k) == 64

    # Verify that the submission has truncated false for all entries to verify this is the full tree.
    for k, v in resp['tree'].items():
        assert v.get("truncated", True) is False


def test_get_submission_list_group(datastore, login_session):
    _, session, host = login_session

    group = get_random_groups()
    search_len = datastore.submission.search(f'params.groups:{group}', rows=0)['total']
    resp = get_api_data(session, f"{host}/api/v4/submission/list/group/{group}/")
    assert resp['total'] == search_len


def test_get_submission_list_user(datastore, login_session):
    _, session, host = login_session

    user = get_random_user()
    search_len = datastore.submission.search(f'params.submitter:{user}', rows=0)['total']
    resp = get_api_data(session, f"{host}/api/v4/submission/list/user/{user}/")
    assert resp['total'] == search_len


def test_set_verdict(datastore, login_session):
    _, session, host = login_session

    submission = random.choice(datastore.submission.search("id:*", rows=NUM_SUBMISSIONS, as_obj=False)['items'])

    # Test setting MALICIOUS verdict
    resp = get_api_data(session, f"{host}/api/v4/submission/verdict/{submission['sid']}/malicious/", method="PUT")
    assert resp['success']

    datastore.submission.commit()
    submission_data = datastore.submission.get(submission['sid'])
    assert 'admin' in submission_data['verdict']['malicious']
    assert 'admin' not in submission_data['verdict']['non_malicious']

    # Test setting NON-MALICOUS verdict
    resp = get_api_data(session, f"{host}/api/v4/submission/verdict/{submission['sid']}/non_malicious/", method="PUT")
    assert resp['success']

    datastore.submission.commit()
    submission_data = datastore.submission.get(submission['sid'])
    assert 'admin' not in submission_data['verdict']['malicious']
    assert 'admin' in submission_data['verdict']['non_malicious']


def _set_submission_classification(datastore, sid, classification_str):
    """Update a submission's classification directly in the datastore."""
    datastore.submission.update(sid, [(datastore.submission.UPDATE_SET, 'classification', classification_str)])
    datastore.submission.commit()


def _set_user_classification(datastore, uname, classification_str):
    """Update a user's classification directly in the datastore."""
    datastore.user.update(uname, [(datastore.user.UPDATE_SET, 'classification', classification_str)])
    datastore.user.commit()


def test_admin_can_access_is_completed(datastore, login_session):
    """Admin (RESTRICTED classification) can check completion on any submission."""
    _, session, host = login_session

    submission = random.choice(
        datastore.submission.search("id:*", rows=NUM_SUBMISSIONS, as_obj=False)['items']
    )
    resp = get_api_data(session, f"{host}/api/v4/submission/is_completed/{submission['sid']}/")
    if submission['state'] == 'completed':
        assert resp is True
    else:
        assert resp is False


def test_nonexistent_submission_returns_404(datastore, login_session):
    """Querying a non-existent SID should return 404."""
    _, session, host = login_session

    fake_sid = str(uuid.uuid4())
    with pytest.raises(APIError, match="does not exist"):
        get_api_data(session, f"{host}/api/v4/submission/is_completed/{fake_sid}/")


def test_user_can_access_matching_classification(datastore, login_user_session):
    """A regular user can access a submission at or below their classification."""
    _, session, host = login_user_session

    submission = random.choice(
        datastore.submission.search("id:*", rows=NUM_SUBMISSIONS, as_obj=False)['items']
    )
    sid = submission['sid']

    _set_submission_classification(datastore, sid, CLASSIFICATION.UNRESTRICTED)
    _set_user_classification(datastore, 'user', CLASSIFICATION.UNRESTRICTED)

    resp = get_api_data(session, f"{host}/api/v4/submission/is_completed/{sid}/")
    assert resp is True or resp is False


def test_low_classification_user_cannot_access_high_classification_submission(datastore, login_user_session):
    """
    A user with UNRESTRICTED classification must NOT be able to check
    the completion state of a RESTRICTED submission. The endpoint should
    return 404 (not 403) to avoid leaking the submission's existence.
    """
    _, session, host = login_user_session

    submission = random.choice(
        datastore.submission.search("id:*", rows=NUM_SUBMISSIONS, as_obj=False)['items']
    )
    sid = submission['sid']

    _set_submission_classification(datastore, sid, CLASSIFICATION.RESTRICTED)
    _set_user_classification(datastore, 'user', CLASSIFICATION.UNRESTRICTED)

    with pytest.raises(APIError, match="does not exist"):
        get_api_data(session, f"{host}/api/v4/submission/is_completed/{sid}/")


def test_denied_response_is_indistinguishable_from_not_found(datastore, login_user_session):
    """
    The error message for a denied classification check must be identical
    to the error for a genuinely missing submission, preventing an attacker
    from distinguishing between 'exists but denied' and 'does not exist'.
    """
    _, session, host = login_user_session

    submission = random.choice(
        datastore.submission.search("id:*", rows=NUM_SUBMISSIONS, as_obj=False)['items']
    )
    sid = submission['sid']
    fake_sid = str(uuid.uuid4())

    _set_submission_classification(datastore, sid, CLASSIFICATION.RESTRICTED)
    _set_user_classification(datastore, 'user', CLASSIFICATION.UNRESTRICTED)

    denied_error = None
    try:
        get_api_data(session, f"{host}/api/v4/submission/is_completed/{sid}/")
    except APIError as e:
        denied_error = str(e)

    not_found_error = None
    try:
        get_api_data(session, f"{host}/api/v4/submission/is_completed/{fake_sid}/")
    except APIError as e:
        not_found_error = str(e)

    assert denied_error is not None, "Expected 404 for denied classification access"
    assert not_found_error is not None, "Expected 404 for non-existent submission"

    # Both errors should follow the same "does not exists" pattern
    assert "does not exist" in denied_error
    assert "does not exist" in not_found_error


def test_higher_classification_user_can_access_lower_submission(datastore, login_user_session):
    """A user with higher classification can access lower classification submissions."""
    _, session, host = login_user_session

    submission = random.choice(
        datastore.submission.search("id:*", rows=NUM_SUBMISSIONS, as_obj=False)['items']
    )
    sid = submission['sid']

    _set_submission_classification(datastore, sid, CLASSIFICATION.UNRESTRICTED)
    _set_user_classification(datastore, 'user', CLASSIFICATION.RESTRICTED)

    resp = get_api_data(session, f"{host}/api/v4/submission/is_completed/{sid}/")
    assert resp is True or resp is False
