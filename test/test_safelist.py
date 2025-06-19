
import hashlib
import json
import random

import pytest
from assemblyline_ui.config import CLASSIFICATION
from conftest import APIError, get_api_data

from assemblyline.common.forge import get_classification
from assemblyline.common.isotime import iso_to_epoch, now_as_iso
from assemblyline.odm.random_data import (
    create_safelists,
    create_users,
    wipe_safelist,
    wipe_users,
)
from assemblyline.odm.randomizer import get_random_hash

add_hash_file = "10" + get_random_hash(62)
add_error_hash = "11" + get_random_hash(62)
update_hash = "12" + get_random_hash(62)
update_conflict_hash = "13" + get_random_hash(62)
source_hash = "14" + get_random_hash(62)

NSRL_SOURCE = {
    "classification": CLASSIFICATION.UNRESTRICTED,
    "name": "NSRL",
    "reason": [
        "Found as test.txt on default windows 10 CD",
        "Found as install.txt on default windows XP CD"
    ],
    "type": "external"}

NSRL2_SOURCE = {
    "classification": CLASSIFICATION.UNRESTRICTED,
    "name": "NSRL2",
    "reason": [
        "File contains only AAAAs..."
    ],
    "type": "external"}

ADMIN_SOURCE = {
    "classification": CLASSIFICATION.UNRESTRICTED,
    "name": "admin",
    "reason": [
        "Generates a lot of FPs",
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

CLASSIFIED_SOURCE = {
    "classification": CLASSIFICATION.RESTRICTED,
    "name": "Classified",
    "reason": [
        "This is a classified reason"
    ],
    "type": "external"}


@pytest.fixture(scope="module")
def datastore(datastore_connection):
    try:
        create_users(datastore_connection)
        create_safelists(datastore_connection)
        yield datastore_connection
    finally:
        wipe_users(datastore_connection)
        wipe_safelist(datastore_connection)


# noinspection PyUnusedLocal
def test_safelist_add_file(datastore, login_session):
    _, session, host = login_session

    # Generate a random safelist
    sl_data = {
        'hashes': {'md5': get_random_hash(32),
                   'sha1': get_random_hash(40),
                   'sha256': add_hash_file},
        'file': {'name': ['file.txt'],
                 'size': random.randint(128, 4096),
                 'type': 'document/text'},
        'sources': [NSRL_SOURCE, ADMIN_SOURCE],
        'type': 'file'
    }

    # Insert it and test return value
    resp = get_api_data(session, f"{host}/api/v4/safelist/", method="PUT", data=json.dumps(sl_data))
    assert resp['success']
    assert resp['op'] == 'add'

    # Load inserted data from DB
    ds_sl = datastore.safelist.get(add_hash_file, as_obj=False)

    # Test dates
    added = ds_sl.pop('added', None)
    updated = ds_sl.pop('updated', None)

    # File item will live forever
    assert ds_sl.pop('expiry_ts', None) is None

    assert added == updated
    assert added is not None and updated is not None

    # Make sure tag and signature are none
    tag = ds_sl.pop('tag', None)
    signature = ds_sl.pop('signature', None)
    assert tag is None
    assert signature is None

    # Test classification
    classification = ds_sl.pop('classification', None)
    assert classification is not None

    # Test enabled
    enabled = ds_sl.pop('enabled', None)
    assert enabled

    # Test rest
    assert ds_sl == sl_data


def test_safelist_add_tag(datastore, login_session):
    _, session, host = login_session

    tag_type = 'network.static.ip'
    tag_value = '127.0.0.1'
    hashed_value = f"{tag_type}: {tag_value}".encode('utf8')

    # Generate a random safelist
    sl_data = {
        'dtl': 15,
        'hashes': {'sha256': hashlib.sha256(hashed_value).hexdigest()},
        'tag': {'type': tag_type,
                'value': tag_value},
        'sources': [NSRL_SOURCE, ADMIN_SOURCE],
        'type': 'tag'
    }

    # Insert it and test return value
    resp = get_api_data(session, f"{host}/api/v4/safelist/", method="PUT", data=json.dumps(sl_data))
    assert resp['success']
    assert resp['op'] == 'add'

    # Load inserted data from DB
    ds_sl = datastore.safelist.get(hashlib.sha256(hashed_value).hexdigest(), as_obj=False)

    # Test dates
    added = ds_sl.pop('added', None)
    updated = ds_sl.pop('updated', None)

    # Tag item will live up to a certain date
    assert ds_sl.pop('expiry_ts', None) is not None

    assert added == updated
    assert added is not None and updated is not None

    # Make sure file and signature are None
    file = ds_sl.pop('file', {})
    signature = ds_sl.pop('signature', None)
    assert file is None
    assert signature is None

    # Test classification
    classification = ds_sl.pop('classification', None)
    assert classification is not None

    # Test enabled
    enabled = ds_sl.pop('enabled', None)
    assert enabled

    for hashtype in ['md5', 'sha1']:
        ds_sl['hashes'].pop(hashtype, None)

    # Test rest, dtl should not exist anymore
    sl_data.pop('dtl', None)
    assert ds_sl == sl_data


def test_safelist_add_signature(datastore, login_session):
    _, session, host = login_session

    sig_name = 'McAfee.Eicar'
    hashed_value = f"signature: {sig_name}".encode('utf8')

    # Generate a random safelist
    sl_data = {
        'hashes': {'sha256': hashlib.sha256(hashed_value).hexdigest()},
        'signature': {'name': sig_name},
        'sources': [ADMIN_SOURCE],
        'type': 'signature'
    }

    # Insert it and test return value
    resp = get_api_data(session, f"{host}/api/v4/safelist/", method="PUT", data=json.dumps(sl_data))
    assert resp['success']
    assert resp['op'] == 'add'

    # Load inserted data from DB
    ds_sl = datastore.safelist.get(hashlib.sha256(hashed_value).hexdigest(), as_obj=False)

    # Test dates
    added = ds_sl.pop('added', None)
    updated = ds_sl.pop('updated', None)

    # Signature item will live forever
    assert ds_sl.pop('expiry_ts', None) is None

    assert added == updated
    assert added is not None and updated is not None

    # Make sure file and signature are None
    file = ds_sl.pop('file', {})
    tag = ds_sl.pop('tag', None)
    assert file is None
    assert tag is None

    # Test classification
    classification = ds_sl.pop('classification', None)
    assert classification is not None

    # Test enabled
    enabled = ds_sl.pop('enabled', None)
    assert enabled

    for hashtype in ['md5', 'sha1']:
        ds_sl['hashes'].pop(hashtype, None)

    # Test rest
    assert ds_sl == sl_data


def test_safelist_add_invalid(datastore, login_session):
    _, session, host = login_session

    # Generate a random safelist
    sl_data = {
        'hashes': {'sha256': add_error_hash},
        'sources': [USER_SOURCE],
        'type': 'file'}

    # Insert it and test return value
    with pytest.raises(APIError) as conflict_exc:
        get_api_data(session, f"{host}/api/v4/safelist/", method="PUT", data=json.dumps(sl_data))

    assert 'for another user' in conflict_exc.value.args[0]


def test_safelist_update(datastore, login_session):
    _, session, host = login_session
    cl_eng = get_classification()

    # Generate a random safelist
    sl_data = {
        'hashes': {'md5': get_random_hash(32),
                   'sha1': get_random_hash(40),
                   'sha256': update_hash},
        'file': {'name': [],
                 'size': random.randint(128, 4096),
                 'type': 'document/text'},
        'sources': [NSRL_SOURCE],
        'type': 'file'
    }

    # Insert it and test return value
    resp = get_api_data(session, f"{host}/api/v4/safelist/", method="PUT", data=json.dumps(sl_data))
    assert resp['success']
    assert resp['op'] == 'add'

    # Load inserted data from DB
    ds_sl = datastore.safelist.get(update_hash, as_obj=False)

    # Test rest
    assert {k: v for k, v in ds_sl.items()
            if k not in ['added', 'updated', 'expiry_ts', 'classification', 'enabled', 'tag', 'signature']} == sl_data

    u_data = {
        'hashes': {'sha256': update_hash},
        'sources': [CLASSIFIED_SOURCE],
        'type': 'file'
    }

    # Insert it and test return value
    resp = get_api_data(session, f"{host}/api/v4/safelist/", method="PUT", data=json.dumps(u_data))
    assert resp['success']
    assert resp['op'] == 'update'

    # Load inserted data from DB
    ds_u = datastore.safelist.get(update_hash, as_obj=False)

    assert ds_u['added'] == ds_sl['added']
    assert iso_to_epoch(ds_u['updated']) > iso_to_epoch(ds_sl['updated'])
    assert ds_u['classification'] == cl_eng.RESTRICTED
    assert len(ds_u['sources']) == 2
    assert CLASSIFIED_SOURCE in ds_u['sources']
    assert NSRL_SOURCE in ds_u['sources']


def test_safelist_update_conflict(datastore, login_session):
    _, session, host = login_session

    # Generate a random safelist
    sl_data = {'hashes': {'sha256': update_conflict_hash}, 'file': {}, 'sources': [ADMIN_SOURCE], 'type': 'file'}

    # Insert it and test return value
    resp = get_api_data(session, f"{host}/api/v4/safelist/",
                        method="PUT", data=json.dumps(sl_data))
    assert resp['success']
    assert resp['op'] == 'add'

    # Insert the same source with a different type
    sl_data['sources'][0]['type'] = 'external'
    with pytest.raises(APIError) as conflict_exc:
        get_api_data(session, f"{host}/api/v4/safelist/",
                     method="PUT", data=json.dumps(sl_data))

    assert 'has a type conflict:' in conflict_exc.value.args[0]


def test_safelist_exist(datastore, login_session):
    _, session, host = login_session

    hash = random.choice(datastore.safelist.search("id:*", fl='id', rows=100, as_obj=False)['items'])['id']

    resp = get_api_data(session, f"{host}/api/v4/safelist/{hash}/")
    assert resp == datastore.safelist.get(hash, as_obj=False)


# noinspection PyUnusedLocal
def test_safelist_invalid(datastore, login_session):
    _, session, host = login_session

    with pytest.raises(APIError) as invalid_exc:
        get_api_data(session, f"{host}/api/v4/safelist/{get_random_hash(12)}/")

    assert 'hash length' in invalid_exc.value.args[0]


# noinspection PyUnusedLocal
def test_safelist_missing(datastore, login_session):
    _, session, host = login_session

    missing_hash = "f" + get_random_hash(63)
    with pytest.raises(APIError) as missing_exc:
        get_api_data(session, f"{host}/api/v4/safelist/{missing_hash}/")

    assert 'not found' in missing_exc.value.args[0]


def test_safelist_delete_hash(datastore, login_session):
    _, session, host = login_session

    hash = random.choice(datastore.safelist.search("*", fl="id", rows=100, as_obj=False)['items'])['id']

    resp = get_api_data(session, f"{host}/api/v4/safelist/{hash}/", method="DELETE")
    assert resp['success']

    assert datastore.safelist.get_if_exists(hash) is None


def test_safelist_expiry(datastore, login_session):
    _, session, host = login_session

    hash = get_api_data(session, f"{host}/api/v4/search/safelist/?query=*&fl=id&rows=1")['items'][0]['id']

    new_expiry = now_as_iso()

    resp = get_api_data(session, f"{host}/api/v4/safelist/expiry/{hash}/", method="PUT", data=json.dumps(new_expiry))
    assert resp['success']

    assert new_expiry[:26] == datastore.safelist.get_if_exists(hash, as_obj=False)['expiry_ts'][:26]

    resp = get_api_data(session, f"{host}/api/v4/safelist/expiry/{hash}/", method="DELETE")
    assert resp['success']

    assert datastore.safelist.get_if_exists(hash, as_obj=False)['expiry_ts'] is None


def test_safelist_source_remove(datastore, login_session):
    _, session, host = login_session

    # Generate a random safelist
    sl_data = {
        'hashes': {
            'md5': get_random_hash(32),
            'sha1': get_random_hash(40),
            'sha256': source_hash
        },
        'file': {'name': ['test.txt'],
                 'size': random.randint(128, 4096),
                 'type': 'document/text'},
        'sources': [NSRL_SOURCE, NSRL2_SOURCE],
        'type': 'file'
    }

    # Insert it and test return value
    resp = get_api_data(session, f"{host}/api/v4/safelist/", method="PUT", data=json.dumps(sl_data))
    assert resp['success']
    assert resp['op'] == 'add'

    assert NSRL2_SOURCE in datastore.safelist.get_if_exists(source_hash, as_obj=False)['sources']

    resp = get_api_data(session, f"{host}/api/v4/safelist/source/{source_hash}/NSRL2/external/", method="DELETE")
    assert resp['success']

    assert NSRL2_SOURCE not in datastore.safelist.get_if_exists(source_hash, as_obj=False)['sources']
