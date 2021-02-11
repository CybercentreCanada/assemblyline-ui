import pytest
import random

from cart import is_cart
from conftest import get_api_data

from assemblyline.common.bundling import create_bundle, BUNDLE_MAGIC
from assemblyline.odm.random_data import create_users, wipe_users, create_submission, wipe_submissions


@pytest.fixture(scope="module")
def datastore(datastore_connection, filestore):
    try:
        create_users(datastore_connection)
        create_submission(datastore_connection, filestore)
        yield datastore_connection
    finally:
        wipe_users(datastore_connection)
        wipe_submissions(datastore_connection, filestore)


# noinspection PyUnusedLocal
def test_create_bundle(datastore, login_session):
    _, session, host = login_session

    sid = random.choice(datastore.submission.search('id:*', rows=100, as_obj=False)['items'])['sid']
    resp = get_api_data(session, f"{host}/api/v4/bundle/{sid}/", raw=True)
    assert is_cart(resp[:256])


# noinspection PyUnusedLocal
def test_import_bundle(datastore, login_session, filestore):
    _, session, host = login_session
    ds = datastore

    # Create a temporary bundle
    submission = random.choice(ds.submission.search('id:*', rows=100, as_obj=False)['items'])
    bundle_file = create_bundle(submission['sid'], working_dir='/tmp/bundle')

    # Delete associated submission
    ds.delete_submission_tree(submission['sid'], transport=filestore)
    ds.error.commit()
    ds.file.commit()
    ds.result.commit()
    ds.submission.commit()

    with open(bundle_file, 'rb') as bfh:
        resp = get_api_data(session, f"{host}/api/v4/bundle/", method="POST", data=bfh.read())
        assert resp['success']

        ds.submission.commit()
        assert submission == random.choice(ds.submission.search('id:*', rows=100, as_obj=False)['items'])
