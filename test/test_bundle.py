import random

import pytest

# noinspection PyUnresolvedReferences
from base import HOST, login_session, get_api_data, create_users, wipe_users, create_services, \
    wipe_services, create_submission, wipe_submissions

from assemblyline.common import forge
from assemblyline.common.bundling import create_bundle, BUNDLE_MAGIC

config = forge.get_config()
ds = forge.get_datastore(config)
fs = forge.get_filestore(config)


def purge_bundle():
    wipe_users(ds)
    wipe_submissions(ds, fs)


@pytest.fixture(scope="module")
def datastore(request):
    create_users(ds)
    create_submission(ds, fs)

    ds.error.commit()
    ds.file.commit()
    ds.result.commit()
    ds.submission.commit()

    request.addfinalizer(purge_bundle)
    return ds


# noinspection PyUnusedLocal
def test_create_bundle(datastore, login_session):
    _, session = login_session

    sid = random.choice(ds.submission.search('id:*', rows=100, as_obj=False)['items'])['sid']
    resp = get_api_data(session, f"{HOST}/api/v4/bundle/{sid}/", raw=True)
    assert resp[:3] == BUNDLE_MAGIC


# noinspection PyUnusedLocal
def test_import_bundle(datastore, login_session):
    _, session = login_session

    # Create a temporary bundle
    submission = random.choice(ds.submission.search('id:*', rows=100, as_obj=False)['items'])
    bundle_file = create_bundle(submission['sid'], working_dir='/tmp/bundle')

    # Delete associated submission
    ds.delete_submission_tree(submission['sid'], transport=fs)
    ds.error.commit()
    ds.file.commit()
    ds.result.commit()
    ds.submission.commit()

    with open(bundle_file, 'rb') as bfh:
        resp = get_api_data(session, f"{HOST}/api/v4/bundle/", method="POST", data=bfh.read())
        assert resp['success']

        ds.submission.commit()
        assert submission == random.choice(ds.submission.search('id:*', rows=100, as_obj=False)['items'])
