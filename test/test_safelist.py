
import json
import random

import pytest

from assemblyline.common.forge import get_classification
from assemblyline.common.isotime import iso_to_epoch
from assemblyline.odm.random_data import create_users, create_safelists, wipe_users, wipe_safelist
from assemblyline.odm.randomizer import get_random_hash
from conftest import APIError, get_api_data

add_hash = "10" + get_random_hash(62)
add_error_hash = "11" + get_random_hash(62)
update_hash = "12" + get_random_hash(62)
update_conflict_hash = "13" + get_random_hash(62)

NSRL_SOURCE = {
    "name": "NSRL",
    "reason": [
        "Found as test.txt on default windows 10 CD",
        "Found as install.txt on default windows XP CD"
    ],
    "type": "external"}

NSRL2_SOURCE = {
    "name": "NSRL2",
    "reason": [
        "File contains only AAAAs..."
    ],
    "type": "external"}

ADMIN_SOURCE = {
    "name": "admin",
    "reason": [
        "Generates a lot of FPs",
    ],
    "type": "user"}

USER_SOURCE = {
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
        create_safelists(datastore_connection)
        yield datastore_connection
    finally:
        wipe_users(datastore_connection)
        wipe_safelist(datastore_connection)


# noinspection PyUnusedLocal
def test_safelist_add(datastore, login_session):
    _, session, host = login_session

    # Generate a random safelist
    wl_data = {
        'fileinfo': {'md5': get_random_hash(32),
                     'sha1': get_random_hash(40),
                     'sha256': add_hash,
                     'size': random.randint(128, 4096),
                     'type': 'document/text'},
        'sources': [NSRL_SOURCE, ADMIN_SOURCE],
    }

    # Insert it and test return value
    resp = get_api_data(session, f"{host}/api/v4/safelist/{add_hash}/", method="PUT", data=json.dumps(wl_data))
    assert resp['success']
    assert resp['op'] == 'add'

    # Load inserted data from DB
    ds_wl = datastore.safelist.get(add_hash, as_obj=False)

    # Test dates
    added = ds_wl.pop('added', None)
    updated = ds_wl.pop('updated', None)
    assert added == updated
    assert added is not None and updated is not None

    # Test classification
    classification = ds_wl.pop('classification', None)
    assert classification is not None

    # Test rest
    assert ds_wl == wl_data


def test_safelist_add_invalid(datastore, login_session):
    _, session, host = login_session

    # Generate a random safelist
    wl_data = {'sources': [USER_SOURCE]}

    # Insert it and test return value
    with pytest.raises(APIError) as conflict_exc:
        get_api_data(session, f"{host}/api/v4/safelist/{add_error_hash}/", method="PUT", data=json.dumps(wl_data))

    assert 'for another user' in conflict_exc.value.args[0]


def test_safelist_update(datastore, login_session):
    _, session, host = login_session
    cl_eng = get_classification()

    # Generate a random safelist
    wl_data = {
        'fileinfo': {'md5': get_random_hash(32),
                     'sha1': get_random_hash(40),
                     'sha256': update_hash,
                     'size': random.randint(128, 4096),
                     'type': 'document/text'},
        'sources': [NSRL_SOURCE],
    }

    # Insert it and test return value
    resp = get_api_data(session, f"{host}/api/v4/safelist/{update_hash}/", method="PUT", data=json.dumps(wl_data))
    assert resp['success']
    assert resp['op'] == 'add'

    # Load inserted data from DB
    ds_wl = datastore.safelist.get(update_hash, as_obj=False)

    # Test rest
    assert {k: v for k, v in ds_wl.items() if k not in ['added', 'updated', 'classification']} == wl_data

    u_data = {
        'classification': cl_eng.RESTRICTED,
        'sources': [NSRL2_SOURCE]
    }

    # Insert it and test return value
    resp = get_api_data(session, f"{host}/api/v4/safelist/{update_hash}/", method="PUT", data=json.dumps(u_data))
    assert resp['success']
    assert resp['op'] == 'update'

    # Load inserted data from DB
    ds_u = datastore.safelist.get(update_hash, as_obj=False)

    assert ds_u['added'] == ds_wl['added']
    assert iso_to_epoch(ds_u['updated']) > iso_to_epoch(ds_wl['updated'])
    assert ds_u['classification'] == cl_eng.RESTRICTED
    assert len(ds_u['sources']) == 2
    assert NSRL2_SOURCE in ds_u['sources']
    assert NSRL_SOURCE in ds_u['sources']


def test_safelist_update_conflict(datastore, login_session):
    _, session, host = login_session

    # Generate a random safelist
    wl_data = {'sources': [ADMIN_SOURCE]}

    # Insert it and test return value
    resp = get_api_data(session, f"{host}/api/v4/safelist/{update_conflict_hash}/",
                        method="PUT", data=json.dumps(wl_data))
    assert resp['success']
    assert resp['op'] == 'add'

    # Insert the same source with a different type
    wl_data['sources'][0]['type'] = 'external'
    with pytest.raises(APIError) as conflict_exc:
        get_api_data(session, f"{host}/api/v4/safelist/{update_conflict_hash}/",
                     method="PUT", data=json.dumps(wl_data))

    assert 'Source type conflict' in conflict_exc.value.args[0]


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
