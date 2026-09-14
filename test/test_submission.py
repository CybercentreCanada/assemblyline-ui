
import pytest
import random
import uuid

from conftest import get_api_data, APIError

from assemblyline.common.forge import get_classification
from assemblyline.odm.models.file import File
from assemblyline.odm.models.result import Result
from assemblyline.odm.models.submission import Submission
from assemblyline.odm.randomizer import get_random_user, get_random_groups, random_minimal_obj
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

    # Verify bidirectional map integrity and deduplication
    for k, values in resp['map'].items():
        assert isinstance(values, list)
        assert len(values) == len(set(values)), f"Duplicate entries found in map for key {k}: {values}"

        if len(k) == 64:
            # File sha256 -> items (attack pattern, heuristic, signature, tag)
            for item_key in values:
                assert item_key in resp['map'], f"Item key {item_key} missing from map"
                assert k in resp['map'][item_key], f"sha256 {k} missing in reverse map for {item_key}"
        else:
            # Item key -> file sha256s
            for sha256 in values:
                assert sha256 in resp['map'], f"sha256 {sha256} missing from map"
                assert k in resp['map'][sha256], f"Item key {k} missing in reverse map for {sha256}"


def test_get_submission_summary_map_properties(datastore, login_session):
    _, session, host = login_session

    test_sha256 = "a" * 64
    file_obj = random_minimal_obj(File)
    file_obj.sha256 = test_sha256
    file_obj.classification = CLASSIFICATION.UNRESTRICTED
    datastore.file.save(test_sha256, file_obj)

    # Result with:
    # 1. Repeated tags in multiple sections (to verify tag deduplication in map[sha256])
    # 2. Attack pattern with empty categories (to verify attack_pattern__ is mapped)
    # 3. Heuristic with signature
    res = random_minimal_obj(Result)
    res.sha256 = test_sha256
    res.classification = CLASSIFICATION.UNRESTRICTED
    res.response.service_name = "test_summary_svc"
    res.response.service_version = "1.0"
    res.result.sections = [
        {
            "auto_collapse": False,
            "body": "section 1",
            "body_format": "TEXT",
            "classification": CLASSIFICATION.UNRESTRICTED,
            "depth": 0,
            "heuristic": {
                "heur_id": "1001",
                "name": "Test Heuristic",
                "attack": [{
                    "attack_id": "T1001",
                    "pattern": "Test Pattern",
                    "categories": []  # Empty categories
                }],
                "signature": [{"name": "test_sig"}],
                "score": 500
            },
            "tags": {"network": {"static": {"ip": ["1.2.3.4"]}}},
            "safelisted_tags": {},
            "title_text": "Section 1"
        },
        {
            "auto_collapse": False,
            "body": "section 2",
            "body_format": "TEXT",
            "classification": CLASSIFICATION.UNRESTRICTED,
            "depth": 0,
            "heuristic": None,
            "tags": {"network": {"static": {"ip": ["1.2.3.4"]}}},  # Duplicate tag on same sha256
            "safelisted_tags": {},
            "title_text": "Section 2"
        }
    ]
    res_key = res.build_key()
    datastore.result.save(res_key, res)

    sub = random_minimal_obj(Submission)
    sub.sid = str(uuid.uuid4())
    sub.files = [{"name": "test.bin", "sha256": test_sha256, "size": 100}]
    sub.results = [res_key]
    sub.state = "completed"
    sub.classification = CLASSIFICATION.UNRESTRICTED
    sub.params.submitter = "admin"
    datastore.submission.save(sub.sid, sub)
    datastore.result.commit()
    datastore.file.commit()
    datastore.submission.commit()

    try:
        resp = get_api_data(session, f"{host}/api/v4/submission/summary/{sub.sid}/")
        out_map = resp['map']

        # 1. Attack pattern with empty categories must be in map
        assert "attack_pattern__T1001" in out_map
        assert test_sha256 in out_map["attack_pattern__T1001"]
        assert "attack_pattern__T1001" in out_map[test_sha256]

        # 2. Duplicate tag must be present in map[sha256] exactly once
        tag_key = "network.static.ip__1.2.3.4"
        assert tag_key in out_map
        assert test_sha256 in out_map[tag_key]
        assert out_map[test_sha256].count(tag_key) == 1

        # 3. Signature must be present in map
        sig_key = "heuristic.signature__test_sig"
        assert sig_key in out_map
        assert test_sha256 in out_map[sig_key]
        assert sig_key in out_map[test_sha256]

        # 4. Entire map is bidirectional and deduplicated
        for k, values in out_map.items():
            assert len(values) == len(set(values)), f"Duplicates found in map[{k}]"
            for v in values:
                assert v in out_map, f"Missing reverse entry for {v}"
                assert k in out_map[v], f"Missing {k} in out_map[{v}]"
    finally:
        datastore.submission.delete(sub.sid)
        datastore.result.delete(res_key)
        datastore.file.delete(test_sha256)
        datastore.submission.commit()
        datastore.result.commit()
        datastore.file.commit()


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
