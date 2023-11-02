
import hashlib
import json
import random

import pytest

from assemblyline.common.forge import get_classification
from assemblyline.common.isotime import iso_to_epoch
from assemblyline.odm.random_data import create_users, create_badlists, wipe_users, wipe_badlist
from assemblyline.odm.randomizer import get_random_hash
from assemblyline_ui.config import CLASSIFICATION
from conftest import APIError, get_api_data

add_hash_file = "10" + get_random_hash(62)
add_error_hash = "11" + get_random_hash(62)
update_hash = "12" + get_random_hash(62)
update_conflict_hash = "13" + get_random_hash(62)

BAD_SOURCE = {
    "classification": CLASSIFICATION.UNRESTRICTED,
    "name": "BAD",
    "reason": [
        "2nd stage for implant BAD",
        "Used by actor BLAH!"
    ],
    "type": "external"}

BAD2_SOURCE = {
    "classification": CLASSIFICATION.UNRESTRICTED,
    "name": "BAD2",
    "reason": [
        "Use for phishing"
    ],
    "type": "external"}

ADMIN_SOURCE = {
    "classification": CLASSIFICATION.UNRESTRICTED,
    "name": "admin",
    "reason": [
        "It's denifitely bad",
    ],
    "type": "user"}

USER_SOURCE = {
    "classification": CLASSIFICATION.UNRESTRICTED,
    "name": "user",
    "reason": [
        "I just feel like it!",
        "I just feel like it!",
    ],
    "type": "user"}


@pytest.fixture(scope="module")
def datastore(datastore_connection):
    try:
        create_users(datastore_connection)
        create_badlists(datastore_connection)
        yield datastore_connection
    finally:
        wipe_users(datastore_connection)
        wipe_badlist(datastore_connection)


# noinspection PyUnusedLocal
def test_badlist_add_file(datastore, login_session):
    _, session, host = login_session

    # Generate a random badlist
    sl_data = {
        'hashes': {'md5': get_random_hash(32),
                   'sha1': get_random_hash(40),
                   'sha256': add_hash_file},
        'file': {'name': ['file.txt'],
                 'size': random.randint(128, 4096),
                 'type': 'document/text'},
        'sources': [BAD_SOURCE, ADMIN_SOURCE],
        'type': 'file'
    }

    # Insert it and test return value
    resp = get_api_data(session, f"{host}/api/v4/badlist/", method="PUT", data=json.dumps(sl_data))
    assert resp['success']
    assert resp['op'] == 'add'

    # Load inserted data from DB
    ds_sl = datastore.badlist.get(add_hash_file, as_obj=False)

    # Test dates
    added = ds_sl.pop('added', None)
    updated = ds_sl.pop('updated', None)
    assert added == updated
    assert added is not None and updated is not None

    # Make sure tag is none
    tag = ds_sl.pop('tag', None)
    assert tag is None

    # Test classification
    classification = ds_sl.pop('classification', None)
    assert classification is not None

    # Test enabled
    enabled = ds_sl.pop('enabled', None)
    assert enabled

    # Test rest
    assert ds_sl == sl_data


def test_badlist_add_tag(datastore, login_session):
    _, session, host = login_session

    tag_type = 'network.static.ip'
    tag_value = '127.0.0.1'
    hashed_value = f"{tag_type}: {tag_value}".encode('utf8')

    # Generate a random badlist
    sl_data = {
        'hashes': {'md5': hashlib.md5(hashed_value).hexdigest(),
                   'sha1': hashlib.sha1(hashed_value).hexdigest(),
                   'sha256': hashlib.sha256(hashed_value).hexdigest()},
        'tag': {'type': tag_type,
                'value': tag_value},
        'sources': [BAD_SOURCE, ADMIN_SOURCE],
        'type': 'tag'
    }

    # Insert it and test return value
    resp = get_api_data(session, f"{host}/api/v4/badlist/", method="PUT", data=json.dumps(sl_data))
    assert resp['success']
    assert resp['op'] == 'add'

    # Load inserted data from DB
    ds_sl = datastore.badlist.get(hashlib.sha256(hashed_value).hexdigest(), as_obj=False)

    # Test dates
    added = ds_sl.pop('added', None)
    updated = ds_sl.pop('updated', None)
    assert added == updated
    assert added is not None and updated is not None

    # Make sure file is None
    file = ds_sl.pop('file', {})
    assert file is None

    # Test classification
    classification = ds_sl.pop('classification', None)
    assert classification is not None

    # Test enabled
    enabled = ds_sl.pop('enabled', None)
    assert enabled

    # Test rest
    assert ds_sl == sl_data


def test_badlist_add_invalid(datastore, login_session):
    _, session, host = login_session

    # Generate a random badlist
    sl_data = {
        'hashes': {'sha256': add_error_hash},
        'sources': [USER_SOURCE],
        'type': 'file'}

    # Insert it and test return value
    with pytest.raises(APIError) as conflict_exc:
        get_api_data(session, f"{host}/api/v4/badlist/", method="PUT", data=json.dumps(sl_data))

    assert 'for another user' in conflict_exc.value.args[0]


def test_badlist_update(datastore, login_session):
    _, session, host = login_session
    cl_eng = get_classification()

    # Generate a random badlist
    sl_data = {
        'hashes': {'md5': get_random_hash(32),
                   'sha1': get_random_hash(40),
                   'sha256': update_hash},
        'file': {'name': [],
                 'size': random.randint(128, 4096),
                 'type': 'document/text'},
        'sources': [BAD_SOURCE],
        'type': 'file'
    }

    # Insert it and test return value
    resp = get_api_data(session, f"{host}/api/v4/badlist/", method="PUT", data=json.dumps(sl_data))
    assert resp['success']
    assert resp['op'] == 'add'

    # Load inserted data from DB
    ds_sl = datastore.badlist.get(update_hash, as_obj=False)

    # Test rest
    assert {k: v for k, v in ds_sl.items()
            if k not in ['added', 'updated', 'classification', 'enabled', 'tag']} == sl_data

    u_data = {
        'classification': cl_eng.RESTRICTED,
        'hashes': {'sha256': update_hash},
        'sources': [BAD2_SOURCE],
        'type': 'file'
    }

    # Insert it and test return value
    resp = get_api_data(session, f"{host}/api/v4/badlist/", method="PUT", data=json.dumps(u_data))
    assert resp['success']
    assert resp['op'] == 'update'

    # Load inserted data from DB
    ds_u = datastore.badlist.get(update_hash, as_obj=False)

    assert ds_u['added'] == ds_sl['added']
    assert iso_to_epoch(ds_u['updated']) > iso_to_epoch(ds_sl['updated'])
    assert ds_u['classification'] == cl_eng.RESTRICTED
    assert len(ds_u['sources']) == 2
    assert BAD2_SOURCE in ds_u['sources']
    assert BAD_SOURCE in ds_u['sources']


def test_badlist_update_conflict(datastore, login_session):
    _, session, host = login_session

    # Generate a random badlist
    sl_data = {'hashes': {'sha256': update_conflict_hash}, 'file': {}, 'sources': [ADMIN_SOURCE], 'type': 'file'}

    # Insert it and test return value
    resp = get_api_data(session, f"{host}/api/v4/badlist/",
                        method="PUT", data=json.dumps(sl_data))
    assert resp['success']
    assert resp['op'] == 'add'

    # Insert the same source with a different type
    sl_data['sources'][0]['type'] = 'external'
    with pytest.raises(APIError) as conflict_exc:
        get_api_data(session, f"{host}/api/v4/badlist/",
                     method="PUT", data=json.dumps(sl_data))

    assert 'has a type conflict:' in conflict_exc.value.args[0]


def test_badlist_exist(datastore, login_session):
    _, session, host = login_session

    hash = random.choice(datastore.badlist.search("id:*", fl='id', rows=100, as_obj=False)['items'])['id']

    resp = get_api_data(session, f"{host}/api/v4/badlist/{hash}/")
    assert resp == datastore.badlist.get(hash, as_obj=False)


# noinspection PyUnusedLocal
def test_badlist_invalid(datastore, login_session):
    _, session, host = login_session

    with pytest.raises(APIError) as invalid_exc:
        get_api_data(session, f"{host}/api/v4/badlist/{get_random_hash(12)}/")

    assert 'hash length' in invalid_exc.value.args[0]


# noinspection PyUnusedLocal
def test_badlist_missing(datastore, login_session):
    _, session, host = login_session

    missing_hash = "f" + get_random_hash(63)
    with pytest.raises(APIError) as missing_exc:
        get_api_data(session, f"{host}/api/v4/badlist/{missing_hash}/")

    assert 'not found' in missing_exc.value.args[0]
