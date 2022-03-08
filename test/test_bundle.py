
import pytest
import random

from cart import is_cart
from conftest import get_api_data

from assemblyline.common import forge
from assemblyline.common.bundling import create_bundle
from assemblyline.odm.random_data import create_users, wipe_users, create_submission, wipe_submissions
from assemblyline.odm.models.alert import Alert
from assemblyline.odm.randomizer import random_model_obj

ALERT_ID = "test_alert_id_ui"


@pytest.fixture(scope="module")
def datastore(datastore_connection, filestore):
    classification = forge.get_classification()
    try:
        create_users(datastore_connection)
        submission = create_submission(datastore_connection, filestore)
        alert = random_model_obj(Alert)
        alert.alert_id = ALERT_ID
        alert.sid = submission.sid
        datastore_connection.alert.save(ALERT_ID, alert)
        yield datastore_connection
    finally:
        wipe_users(datastore_connection)
        wipe_submissions(datastore_connection, filestore)
        datastore_connection.alert.delete(ALERT_ID)


# noinspection PyUnusedLocal
def test_alert_create_bundle(datastore, login_session):
    _, session, host = login_session

    resp = get_api_data(session, f"{host}/api/v4/bundle/{ALERT_ID}/?use_alert", raw=True)
    assert is_cart(resp[:256])


# noinspection PyUnusedLocal
def test_alert_import_bundle(datastore, login_session, filestore):
    _, session, host = login_session
    ds = datastore

    # Create a temporary bundle
    alert = ds.alert.get_if_exists(ALERT_ID, as_obj=False)
    submission = ds.submission.get_if_exists(alert['sid'], as_obj=False)
    bundle_file = create_bundle(ALERT_ID, working_dir='/tmp/bundle', use_alert=True)

    # Delete associated alert and submission
    ds.alert.delete(ALERT_ID)
    ds.delete_submission_tree(alert['sid'], transport=filestore)
    ds.alert.commit()
    ds.error.commit()
    ds.file.commit()
    ds.result.commit()
    ds.submission.commit()

    with open(bundle_file, 'rb') as bfh:
        resp = get_api_data(session, f"{host}/api/v4/bundle/", method="POST", data=bfh.read())
        assert resp['success']

        ds.submission.commit()
        new_submission = ds.submission.get_if_exists(alert['sid'], as_obj=False)
        assert new_submission['sid'] == alert['sid']
        assert 'bundle.source' in new_submission['metadata']

        new_alert = ds.alert.get_if_exists(ALERT_ID, as_obj=False)
        assert new_alert['alert_id'] == ALERT_ID
        assert new_alert['sid'] == submission['sid']


# noinspection PyUnusedLocal
def test_submission_create_bundle(datastore, login_session):
    _, session, host = login_session

    sid = random.choice(datastore.submission.search('id:*', rows=100, as_obj=False)['items'])['sid']
    resp = get_api_data(session, f"{host}/api/v4/bundle/{sid}/", raw=True)
    assert is_cart(resp[:256])


# noinspection PyUnusedLocal
def test_submission_import_bundle(datastore, login_session, filestore):
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
