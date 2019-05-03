
import pytest
import random

# noinspection PyUnresolvedReferences
from base import HOST, login_session, get_api_data, create_users, wipe_users, create_services, \
    wipe_services, create_submission, wipe_submissions

from assemblyline.common import forge
from assemblyline.odm.randomizer import get_random_user, get_random_groups


NUM_SUBMISSIONS = 10
config = forge.get_config()
ds = forge.get_datastore(config)
fs = forge.get_filestore(config)
complete_file_list = []


def purge_submission():
    wipe_users(ds)
    wipe_submissions(ds)

    for f in complete_file_list:
        fs.delete(f)


@pytest.fixture(scope="module")
def datastore(request):
    create_users(ds)

    for _ in range(NUM_SUBMISSIONS):
        related_files = create_submission(ds)
        complete_file_list.extend(related_files)
        for f in related_files:
            fs.put(f, f)

    ds.error.commit()
    ds.file.commit()
    ds.result.commit()
    ds.submission.commit()

    request.addfinalizer(purge_submission)
    return ds


# noinspection PyUnusedLocal
def test_delete_submission(datastore, login_session):
    _, session = login_session

    submission = random.choice(ds.submission.search("id:*", rows=NUM_SUBMISSIONS, as_obj=False)['items'])
    resp = get_api_data(session, f"{HOST}/api/v4/submission/{submission['sid']}/", method="DELETE")
    assert resp['success']

    ds.error.commit()
    ds.file.commit()
    ds.result.commit()
    ds.submission.commit()

    for s in ds.submission.search("id:*", rows=NUM_SUBMISSIONS, as_obj=False)['items']:
        assert s['sid'] != submission['sid']


# noinspection PyUnusedLocal
def test_get_submission_file_result(datastore, login_session):
    _, session = login_session

    sid = random.choice(ds.submission.search("id:*", fl='id', rows=NUM_SUBMISSIONS, as_obj=False)['items'])['id']
    submission = ds.submission.get(sid)
    sha256 = random.choice(submission.results)[:64]
    resp = get_api_data(session, f"{HOST}/api/v4/submission/{sid}/file/{sha256}/")
    assert len(resp['errors']) == len([x for x in submission.errors if x.startswith(sha256)])
    assert len(resp['results']) == len([x for x in submission.results if x.startswith(sha256)])


# noinspection PyUnusedLocal
def test_get_submission(datastore, login_session):
    _, session = login_session

    submission = random.choice(ds.submission.search("id:*", rows=NUM_SUBMISSIONS, as_obj=False)['items'])
    resp = get_api_data(session, f"{HOST}/api/v4/submission/{submission['sid']}/")
    assert resp['sid'] == submission['sid']
    assert resp['params']['description'] == submission['params']['description']



# noinspection PyUnusedLocal
def test_get_submission_is_completed(datastore, login_session):
    _, session = login_session

    submission = random.choice(ds.submission.search("id:*", rows=NUM_SUBMISSIONS, as_obj=False)['items'])
    resp = get_api_data(session, f"{HOST}/api/v4/submission/is_completed/{submission['sid']}/")
    if submission['state'] == 'completed':
        assert resp is True
    else:
        assert resp is False


# noinspection PyUnusedLocal
def test_get_submission_full(datastore, login_session):
    _, session = login_session

    submission = random.choice(ds.submission.search("id:*", rows=NUM_SUBMISSIONS, as_obj=False)['items'])
    resp = get_api_data(session, f"{HOST}/api/v4/submission/full/{submission['sid']}/")
    assert resp['sid'] == submission['sid']
    assert resp['params']['description'] == submission['params']['description']
    assert isinstance(resp['errors'], dict)
    assert isinstance(resp['results'], dict)
    assert isinstance(resp['file_tree'], dict)
    assert isinstance(resp['file_infos'], dict)

# noinspection PyUnusedLocal
def test_get_submission_summary(datastore, login_session):
    _, session = login_session

    submission = random.choice(ds.submission.search("id:*", rows=NUM_SUBMISSIONS, as_obj=False)['items'])
    resp = get_api_data(session, f"{HOST}/api/v4/submission/summary/{submission['sid']}/")
    assert isinstance(resp['map'], dict)
    assert isinstance(resp['tags'], dict)


# noinspection PyUnusedLocal
def test_get_submission_tree(datastore, login_session):
    _, session = login_session

    submission = random.choice(ds.submission.search("id:*", rows=NUM_SUBMISSIONS, as_obj=False)['items'])
    resp = get_api_data(session, f"{HOST}/api/v4/submission/tree/{submission['sid']}/")
    assert isinstance(resp, dict)
    for k in resp:
        assert len(k) == 64


# noinspection PyUnusedLocal
def test_get_submission_list_group(datastore, login_session):
    _, session = login_session

    group = get_random_groups()
    search_len = ds.submission.search(f'params.groups:{group}', rows=0)['total']
    resp = get_api_data(session, f"{HOST}/api/v4/submission/list/group/{group}/")
    assert resp['total'] == search_len


# noinspection PyUnusedLocal
def test_get_submission_list_user(datastore, login_session):
    _, session = login_session

    user = get_random_user()
    search_len = ds.submission.search(f'params.submitter:{user}', rows=0)['total']
    resp = get_api_data(session, f"{HOST}/api/v4/submission/list/user/{user}/")
    assert resp['total'] == search_len
