import json
import pytest
import random

from conftest import APIError, get_api_data

from assemblyline.common.forge import get_classification
from assemblyline_ui.helper.user import load_user_settings
from assemblyline.odm.models.user import User
from assemblyline.odm.models.user_favorites import Favorite, UserFavorites
from assemblyline.odm.randomizer import random_model_obj
from assemblyline.odm.random_data import create_users, wipe_users

CLASSIFICATION = get_classification()
AVATAR = "AVATAR!"
NUM_FAVS = 10
NUM_USERS = 5
FAV_TYPES = ['alert', 'error', 'search', 'signature', 'submission']
user_list = []


@pytest.fixture(scope="module")
def datastore(datastore_connection):
    global user_list
    ds = datastore_connection
    try:
        create_users(ds)

        data = {
            'alert': [],
            'error': [],
            'search': [],
            'signature': [],
            'submission': [],
        }
        for x in range(NUM_FAVS):
            f = random_model_obj(Favorite)
            f.name = f"test_{x+1}"
            for key in data:
                data[key].append(f)

        ds.user_favorites.save('admin', data)
        ds.user_favorites.save('user', data)

        for x in range(NUM_USERS):
            u = random_model_obj(User)
            u.uname = f"test_{x+1}"
            ds.user.save(u.uname, u)
            ds.user_favorites.save(u.uname, data)
            ds.user_avatar.save(u.uname, AVATAR)
            user_list.append(u.uname)

        yield ds
    finally:
        wipe_users(ds)


# noinspection PyUnusedLocal
def test_add_favorite(datastore, login_session):
    _, session, host = login_session
    username = random.choice(user_list)

    data = random_model_obj(Favorite).as_primitives()
    data['created_by'] = 'admin'
    fav_type = random.choice(FAV_TYPES)

    resp = get_api_data(session, f"{host}/api/v4/user/favorites/{username}/{fav_type}/",
                        method="PUT", data=json.dumps(data))
    assert resp['success']

    datastore.user_favorites.commit()

    favs = datastore.user_favorites.get(username, as_obj=False)

    # Normalize classification
    if data.get('classification'):
        data['classification'] = CLASSIFICATION.normalize_classification(data['classification'])
        for item in favs[fav_type]:
            item['classification'] = CLASSIFICATION.normalize_classification(item['classification'])

    assert data in favs[fav_type]


# noinspection PyUnusedLocal
def test_add_user(datastore, login_session):
    _, session, host = login_session

    u = random_model_obj(User)
    u.uname = "TEST_ADD"

    resp = get_api_data(session, f"{host}/api/v4/user/{u.uname}/", method="PUT", data=json.dumps(u.as_primitives()))
    assert resp['success']

    datastore.user.commit()
    new_user = datastore.user.get(u.uname)
    assert new_user == u


# noinspection PyUnusedLocal
def test_agree_to_tos(datastore, login_session):
    _, session, host = login_session
    username = random.choice(user_list)

    with pytest.raises(APIError):
        resp = get_api_data(session, f"{host}/api/v4/user/tos/{username}/")

    resp = get_api_data(session, f"{host}/api/v4/user/tos/admin/")
    assert resp['success']


# noinspection PyUnusedLocal
def test_get_user(datastore, login_session):
    _, session, host = login_session
    username = random.choice(user_list)

    resp = get_api_data(session, f"{host}/api/v4/user/{username}/")
    new_user = datastore.user.get(username, as_obj=False)

    assert resp['name'] == new_user['name']
    assert resp['uname'] == new_user['uname']
    assert 'otp_sk' not in resp
    assert '2fa_enabled' in resp
    assert 'security_token_enabled' in resp
    assert sorted(resp['security_tokens']) == sorted(list(new_user['security_tokens'].keys()))


# noinspection PyUnusedLocal
def test_get_user_avatar(datastore, login_session):
    _, session, host = login_session
    username = random.choice(user_list)

    resp = get_api_data(session, f"{host}/api/v4/user/avatar/{username}/")
    assert resp == AVATAR


# noinspection PyUnusedLocal
def test_get_user_favorites(datastore, login_session):
    _, session, host = login_session
    username = random.choice(user_list)

    resp = get_api_data(session, f"{host}/api/v4/user/favorites/{username}/")
    assert sorted(list(resp.keys())) == FAV_TYPES
    for ft in FAV_TYPES:
        assert len(resp[ft]) >= NUM_FAVS - 1


# noinspection PyUnusedLocal
def test_get_user_settings(datastore, login_session):
    _, session, host = login_session
    username = random.choice(user_list)

    resp = get_api_data(session, f"{host}/api/v4/user/settings/{username}/")
    assert {'deep_scan', 'download_encoding', 'ignore_cache'}.issubset(set(resp.keys()))


# noinspection PyUnusedLocal
def test_get_user_submission_params(datastore, login_session):
    _, session, host = login_session
    username = random.choice(user_list)

    resp = get_api_data(session, f"{host}/api/v4/user/submission_params/{username}/")
    assert not {'download_encoding'}.issubset(set(resp.keys()))
    assert {'deep_scan', 'groups', 'ignore_cache', 'submitter'}.issubset(set(resp.keys()))
    assert resp['submitter'] == username


# noinspection PyUnusedLocal
def test_list_users(datastore, login_session):
    _, session, host = login_session

    full_ulist = user_list + ['admin', 'user', 'TEST_ADD']
    resp = get_api_data(session, f"{host}/api/v4/user/list/")
    assert resp['total'] >= NUM_USERS
    for u in resp['items']:
        assert u['uname'] in full_ulist


# noinspection PyUnusedLocal
def test_remove_user(datastore, login_session):
    _, session, host = login_session
    username = random.choice(user_list)
    user_list.remove(username)

    resp = get_api_data(session, f"{host}/api/v4/user/{username}/", method="DELETE")
    assert resp['success']

    datastore.user.commit()
    datastore.user_avatar.commit()
    datastore.user_favorites.commit()
    datastore.user_settings.commit()

    assert datastore.user.get(username) is None
    assert datastore.user_avatar.get(username) is None
    assert datastore.user_favorites.get(username) is None
    assert datastore.user_settings.get(username) is None


# noinspection PyUnusedLocal
def test_remove_user_favorite(datastore, login_session):
    _, session, host = login_session
    username = random.choice(user_list)
    fav_type = random.choice(FAV_TYPES)
    to_be_removed = f"test_{random.randint(1, NUM_FAVS)}"

    resp = get_api_data(session, f"{host}/api/v4/user/favorites/{username}/{fav_type}/",
                        method="DELETE", data=json.dumps(to_be_removed))
    assert resp['success']

    datastore.user_favorites.commit()
    user_favs = datastore.user_favorites.get(username, as_obj=False)
    for f in user_favs[fav_type]:
        assert f['name'] != to_be_removed


# noinspection PyUnusedLocal
def test_set_user(datastore, login_session):
    _, session, host = login_session
    username = random.choice(user_list)

    u = random_model_obj(User).as_primitives()
    u['uname'] = username

    resp = get_api_data(session, f"{host}/api/v4/user/{username}/", method="POST", data=json.dumps(u))
    assert resp['success']

    datastore.user.commit()

    new_user = datastore.user.get(username, as_obj=False)
    for k in ['apikeys', 'otp_sk', 'password', 'security_tokens']:
        u.pop(k)
        new_user.pop(k)

    # Normalize classification
    new_user['classification'] = CLASSIFICATION.normalize_classification(new_user['classification'])
    u['classification'] = CLASSIFICATION.normalize_classification(u['classification'])

    for k in u.keys():
        assert u[k] == new_user[k]


# noinspection PyUnusedLocal
def test_set_user_avatar(datastore, login_session):
    _, session, host = login_session

    new_avatar = "NEW AVATAR@!"

    resp = get_api_data(session, f"{host}/api/v4/user/avatar/admin/", method="POST", data=new_avatar)
    assert resp['success']

    datastore.user_avatar.commit()
    assert new_avatar == datastore.user_avatar.get('admin')


# noinspection PyUnusedLocal
def test_set_user_favorites(datastore, login_session):
    _, session, host = login_session
    username = random.choice(user_list)

    favs = random_model_obj(UserFavorites).as_primitives()
    resp = get_api_data(session, f"{host}/api/v4/user/favorites/{username}/", method="POST", data=json.dumps(favs))
    assert resp['success']

    datastore.user_favorites.commit()
    user_favs = datastore.user_favorites.get(username, as_obj=False)

    # Normalize classification
    [fav.update({'classification': CLASSIFICATION.normalize_classification(fav['classification'])})
        for fav_type in list(user_favs.keys())
        for fav in user_favs[fav_type]]

    favs = {key: sorted([sorted(x.items()) for x in value]) for key, value in favs.items()}
    user_favs = {key: sorted([sorted(x.items()) for x in value]) for key, value in user_favs.items()}

    assert favs == user_favs


# noinspection PyUnusedLocal
def test_set_user_settings(datastore, login_session):
    _, session, host = login_session
    username = random.choice(user_list)

    uset = load_user_settings({'uname': username})
    uset['expand_min_score'] = 111
    uset['priority'] = 111

    resp = get_api_data(session, f"{host}/api/v4/user/settings/{username}/", method="POST", data=json.dumps(uset))
    assert resp['success']

    datastore.user_settings.commit()
    assert uset == load_user_settings({'uname': username})
