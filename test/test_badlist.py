
import hashlib
import json
import random

import pytest
from assemblyline_ui.config import CLASSIFICATION
from conftest import APIError, get_api_data

from assemblyline.common.forge import get_classification
from assemblyline.common.isotime import iso_to_epoch, now_as_iso
from assemblyline.odm.random_data import (
    create_badlists,
    create_users,
    wipe_badlist,
    wipe_users,
)
from assemblyline.odm.randomizer import get_random_hash

add_hash_file = "10" + get_random_hash(62)
add_error_hash = "11" + get_random_hash(62)
update_hash = "12" + get_random_hash(62)
update_conflict_hash = "13" + get_random_hash(62)
source_hash = "14" + get_random_hash(62)

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
        'attribution': None,
        'hashes': {'md5': get_random_hash(32),
                   'sha1': get_random_hash(40),
                   'sha256': add_hash_file,
                   'ssdeep': None,
                   'tlsh': None},
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

    # File item will live forever
    assert ds_sl.pop('expiry_ts', None) is None

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
        'attribution': {
            'actor': ["SOMEONE!"],
            'campaign': None,
            'category': None,
            'exploit': None,
            'implant': None,
            'family': None,
            'network': None
        },
        'dtl': 15,
        'hashes': {'sha256': hashlib.sha256(hashed_value).hexdigest()},
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

    # Tag item will live up to a certain date
    assert ds_sl.pop('expiry_ts', None) is not None

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

    for hashtype in ['md5', 'sha1', 'ssdeep', 'tlsh']:
        ds_sl['hashes'].pop(hashtype, None)

    # Test rest, (dtl should be gone)
    sl_data.pop('dtl', None)
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
        'attribution': {
            'actor': None,
            'campaign': None,
            'category': None,
            'exploit': None,
            'implant': ['BAD'],
            'family': None,
            'network': None},
        'hashes': {'md5': get_random_hash(32),
                   'sha1': get_random_hash(40),
                   'sha256': update_hash,
                   'ssdeep': None,
                   'tlsh': None},
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
            if k not in ['added', 'updated', 'expiry_ts', 'classification', 'enabled', 'tag']} == sl_data

    u_data = {
        'attribution': {'implant': ['TEST'], 'actor': ['TEST']},
        'hashes': {'sha256': update_hash, 'tlsh': 'faketlsh'},
        'sources': [CLASSIFIED_SOURCE],
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
    assert CLASSIFIED_SOURCE in ds_u['sources']
    assert BAD_SOURCE in ds_u['sources']
    assert 'TEST' in ds_u['attribution']['implant']
    assert 'BAD' in ds_u['attribution']['implant']
    assert 'TEST' in ds_u['attribution']['actor']
    assert 'faketlsh' in ds_u['hashes']['tlsh']


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

    assert 'hash was not found' in invalid_exc.value.args[0]


# noinspection PyUnusedLocal
def test_badlist_missing(datastore, login_session):
    _, session, host = login_session

    missing_hash = "f" + get_random_hash(63)
    with pytest.raises(APIError) as missing_exc:
        get_api_data(session, f"{host}/api/v4/badlist/{missing_hash}/")

    assert 'not found' in missing_exc.value.args[0]


def test_badlist_similar_ssdeep(datastore, login_session):
    _, session, host = login_session

    hash = random.choice(datastore.badlist.search("type:file AND hashes.ssdeep:*", fl='hashes.ssdeep',
                         rows=100, as_obj=False)['items'])['hashes']['ssdeep']

    resp = get_api_data(session, f"{host}/api/v4/badlist/ssdeep/{hash}/")
    assert len(resp) > 0


def test_badlist_similar_tlsh(datastore, login_session):
    _, session, host = login_session

    hash = random.choice(datastore.badlist.search("type:file AND hashes.tlsh:*", fl='hashes.tlsh',
                         rows=100, as_obj=False)['items'])['hashes']['tlsh']

    resp = get_api_data(session, f"{host}/api/v4/badlist/tlsh/{hash}/")
    assert len(resp) > 0


def test_badlist_delete_hash(datastore, login_session):
    _, session, host = login_session

    hash = random.choice(datastore.badlist.search("*", fl="id", rows=100, as_obj=False)['items'])['id']

    resp = get_api_data(session, f"{host}/api/v4/badlist/{hash}/", method="DELETE")
    assert resp['success']

    assert datastore.badlist.get_if_exists(hash) is None


def test_badlist_attribution(datastore, login_session):
    _, session, host = login_session
    badlist_items = datastore.badlist.search("attribution.actor:*",
                                             fl="id,attribution.actor", rows=100, as_obj=False)['items']
    while True:
        item = random.choice(badlist_items)

        actor = random.choice(item['attribution']['actor'])
        hash = item['id']

        try:
            # Test removing attribution from the hash in the Badlist
            resp = get_api_data(session, f"{host}/api/v4/badlist/attribution/{hash}/actor/{actor}/", method="DELETE")
            break
        except APIError:
            # TODO: Investigate why in some cases the API thinks the hash doesn't exist
            pass

    assert resp['success']

    assert actor not in datastore.badlist.get_if_exists(hash).attribution.actor

    resp = get_api_data(session, f"{host}/api/v4/badlist/attribution/{hash}/actor/{actor}/", method="PUT")
    assert resp['success']

    assert actor in datastore.badlist.get_if_exists(hash).attribution.actor


def test_badlist_expiry(datastore, login_session):
    _, session, host = login_session

    hash = get_api_data(session, f"{host}/api/v4/search/badlist/?query=*&fl=id&rows=1")['items'][0]['id']

    new_expiry = now_as_iso()

    resp = get_api_data(session, f"{host}/api/v4/badlist/expiry/{hash}/", method="PUT", data=json.dumps(new_expiry))
    assert resp['success']

    assert new_expiry[:26] == datastore.badlist.get_if_exists(hash, as_obj=False)['expiry_ts'][:26]

    resp = get_api_data(session, f"{host}/api/v4/badlist/expiry/{hash}/", method="DELETE")
    assert resp['success']

    assert datastore.badlist.get_if_exists(hash, as_obj=False)['expiry_ts'] is None


def test_badlist_source_remove(datastore, login_session):
    _, session, host = login_session

    # Generate a random badlist
    sl_data = {
        'hashes': {
            'md5': get_random_hash(32),
            'sha1': get_random_hash(40),
            'sha256': source_hash
        },
        'file': {'name': ['test.txt'],
                 'size': random.randint(128, 4096),
                 'type': 'document/text'},
        'sources': [BAD_SOURCE, BAD2_SOURCE],
        'type': 'file'
    }

    # Insert it and test return value
    resp = get_api_data(session, f"{host}/api/v4/badlist/", method="PUT", data=json.dumps(sl_data))
    assert resp['success']
    assert resp['op'] == 'add'

    assert BAD2_SOURCE in datastore.badlist.get_if_exists(source_hash, as_obj=False)['sources']

    resp = get_api_data(session, f"{host}/api/v4/badlist/source/{source_hash}/BAD2/external/", method="DELETE")
    assert resp['success']

    assert BAD2_SOURCE not in datastore.badlist.get_if_exists(source_hash, as_obj=False)['sources']
