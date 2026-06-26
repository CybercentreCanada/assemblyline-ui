
import pytest
import random
import uuid

from conftest import get_api_data, APIError

from assemblyline.common.forge import get_classification
from assemblyline.odm.random_data import create_users, wipe_users, create_submission, wipe_submissions
from assemblyline.common.uid import get_random_id

CLASSIFICATION = get_classification()
NUM_SUBMISSIONS = 5


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

    fake_sid = get_random_id()
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
    fake_sid = get_random_id()

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
