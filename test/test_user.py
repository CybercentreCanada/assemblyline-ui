import json
import random

import pytest
from assemblyline.common.forge import get_classification
from assemblyline.common.security import verify_password
from assemblyline.odm.models.apikey import Apikey, get_apikey_id
from assemblyline.odm.models.user import User
from assemblyline.odm.models.user_favorites import Favorite, UserFavorites
from assemblyline.odm.models.user_settings import (
    DEFAULT_SUBMISSION_PROFILE_SETTINGS,
    DEFAULT_USER_PROFILE_SETTINGS,
    UserSettings,
)
from assemblyline.odm.random_data import create_users, wipe_users
from assemblyline.odm.randomizer import random_model_obj
from assemblyline_ui.helper.user import load_user_settings
from conftest import APIError, get_api_data

CLASSIFICATION = get_classification()
AVATAR = "AVATAR!"
NUM_FAVS = 10
NUM_USERS = 5
NUM_KEYS = 2
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
            for items in data.values():
                items.append(f)

        ds.user_favorites.save('admin', data)
        ds.user_favorites.save('user', data)
        ds.user_favorites.save('__global__', data)

        for x in range(NUM_USERS):
            u = random_model_obj(User)
            u.uname = f"test_{x+1}"
            ds.user.save(u.uname, u)
            ds.user_favorites.save(u.uname, data)
            ds.user_avatar.save(u.uname, AVATAR)
            ds.user_settings.save(u.uname, random_model_obj(UserSettings))
            user_list.append(u.uname)

            for y in range(NUM_KEYS):
                key_name = f"testkey_{y+1}"
                key_data = random_model_obj(Apikey)
                key_id = get_apikey_id(key_name, u.uname)
                key_data.uname = u.name
                key_data.key_name = key_name

                ds.apikey.save(key_id, key_data)

        yield ds
    finally:
        wipe_users(ds)


# noinspection PyUnusedLocal
@pytest.mark.parametrize("public", [True, False], ids=["public=true", "public=false"])
def test_add_favorite(datastore, login_session, login_user_session, public):
    _, session, host = login_session
    username = random.choice(user_list) if not public else "__global__"

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

    if public:
        # Attempt to change a global favourite set by the administrator
        _, session, host = login_session = login_user_session
        data['created_by'] = 'user'
        resp = get_api_data(session, f"{host}/api/v4/user/favorites/{username}/{fav_type}/",
                            method="PUT", data=json.dumps(data))
        assert resp['success']

        datastore.user_favorites.commit()
        for fav in datastore.user_favorites.get(username, as_obj=False)[fav_type]:
            if fav["name"] == data["name"]:
                assert fav["created_by"] == "admin"
                break


# noinspection PyUnusedLocal
def test_add_user(datastore, login_session):
    _, session, host = login_session

    u = random_model_obj(User)

    u.uname = "TEST_ADD"

    resp = get_api_data(session, f"{host}/api/v4/user/{u.uname}/", method="PUT", data=json.dumps(u.as_primitives()))
    assert resp['success']

    datastore.user.commit()
    datastore.apikey.commit()

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


@pytest.mark.parametrize("public", [True, False], ids=["public=true", "public=false"])
def test_get_user_favorites(datastore, login_session, public):
    _, session, host = login_session
    username = random.choice(user_list) if not public else '__global__'

    resp = get_api_data(session, f"{host}/api/v4/user/favorites/{username}/")
    assert sorted(list(resp.keys())) == FAV_TYPES
    for ft in FAV_TYPES:
        assert len(resp[ft]) >= NUM_FAVS - 1


# noinspection PyUnusedLocal
def test_get_user_settings(datastore, login_session):
    _, session, host = login_session
    username = random.choice(user_list)

    resp = get_api_data(session, f"{host}/api/v4/user/settings/{username}/")
    # Ensure general settings are present
    assert set(DEFAULT_USER_PROFILE_SETTINGS.keys()).issubset(set(resp.keys()))

    # Ensure submission settings are present under "submission_profiles"
    for submission_profile in resp['submission_profiles'].values():
        assert set(DEFAULT_SUBMISSION_PROFILE_SETTINGS.keys()).issubset(set(submission_profile.keys()))


# noinspection PyUnusedLocal
def test_get_user_submission_params(datastore, login_session):
    _, session, host = login_session
    username = random.choice(user_list)

    # Get submission parameter settings for user based on profile
    resp = get_api_data(session, f"{host}/api/v4/user/submission_params/{username}/static/")
    assert not {'download_encoding'}.issubset(set(resp.keys()))
    assert {'deep_scan', 'groups', 'ignore_cache', 'submitter'}.issubset(set(resp.keys()))
    assert resp['submitter'] == username

    # Ensure API handles missing profiles
    with pytest.raises(APIError):
        resp = get_api_data(session, f"{host}/api/v4/user/submission_params/{username}/random/")


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
    datastore.apikey.commit()

    result = datastore.apikey.search(f"uname:{username}")

    assert datastore.user.get(username) is None
    assert datastore.user_avatar.get(username) is None
    assert datastore.user_favorites.get(username) is None
    assert datastore.user_settings.get(username) is None
    assert result["total"] == 0


# noinspection PyUnusedLocal
@pytest.mark.parametrize("public", [True, False], ids=["public=true", "public=false"])
def test_remove_user_favorite(datastore, login_session, login_user_session, public):
    _, session, host = login_session
    username = random.choice(user_list) if not public else "__global__"
    fav_type = random.choice(FAV_TYPES)
    to_be_removed = f"test_{random.randint(1, NUM_FAVS)}"

    if public:
        # Simulate a user trying to remove a global favourite that they don't own
        for f in datastore.user_favorites.get("__global__", as_obj=False)[fav_type]:
            if f['created_by'] != "user":
                to_be_removed = f["name"]
                break

        __, user_session, host = login_user_session
        with pytest.raises(APIError, match="You are not allowed to remove favorites for another user than yourself."):
            resp = get_api_data(user_session, f"{host}/api/v4/user/favorites/{username}/{fav_type}/",
                                method="DELETE", data=json.dumps(to_be_removed))

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

    # Omit setting identity_id for user (API shouldn't crash if identity_id is missing)
    u.pop('identity_id')

    resp = get_api_data(session, f"{host}/api/v4/user/{username}/", method="POST", data=json.dumps(u))
    assert resp['success']

    datastore.user.commit()

    new_user = datastore.user.get(username, as_obj=False)
    for k in ['otp_sk', 'password', 'security_tokens']:
        u.pop(k)
        new_user.pop(k)

    # Normalize classification
    new_user['classification'] = CLASSIFICATION.normalize_classification(new_user['classification'])
    u['classification'] = CLASSIFICATION.normalize_classification(u['classification'])

    for k, value in u.items():
        assert value == new_user[k]


# noinspection PyUnusedLocal
def test_user_update_user(datastore, login_user_session):
    login_data, session, host = login_user_session
    username = login_data['username']

    # Add an identity_id to the user to ensure it doesn't interfere with user access
    user_data = datastore.user.get(username)
    user_data.identity_id = str(random.random())
    datastore.user.save(username, user_data)

    # Get the starting user data
    user = get_api_data(session, f"{host}/api/v4/user/{username}/")

    try:
        # Do a noop update, we should always be able to just send back what we got from the api
        resp = get_api_data(session, f"{host}/api/v4/user/{username}/", method="POST", data=json.dumps(user))
        assert resp['success']

        # Try to adjust quota as a non-admin
        modified = dict(user)
        modified['api_daily_quota'] += 1000
        with pytest.raises(APIError, match=r'.*Only Administrators can change .*api_daily_quota.*'):
            get_api_data(session, f"{host}/api/v4/user/{username}/", method="POST", data=json.dumps(modified))

        # Change the user name and password
        modified = dict(user)
        modified['name'] = "Orange Cat " + str(random.random())
        modified['new_pass'] = "2cool4passwords" + str(random.random())
        resp = get_api_data(session, f"{host}/api/v4/user/{username}/", method="POST", data=json.dumps(modified))
        assert resp['success']

        # Check that the changes were applied by directly checking the database
        datastore.user.commit()
        new_user = datastore.user.get(username, as_obj=False)
        assert verify_password(modified.pop('new_pass'), new_user['password'])
        assert new_user['name'] == modified['name']

    finally:
        # Revert the user name change
        resp = get_api_data(session, f"{host}/api/v4/user/{username}/", method="POST", data=json.dumps(user))
        assert resp['success']


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
    for fav_type in list(user_favs.keys()):
        for fav in user_favs[fav_type]:
            fav.update({'classification': CLASSIFICATION.normalize_classification(fav['classification'])})

    favs = {key: sorted([sorted(x.items()) for x in value]) for key, value in favs.items()}
    user_favs = {key: sorted([sorted(x.items()) for x in value]) for key, value in user_favs.items()}

    assert favs == user_favs


# noinspection PyUnusedLocal
@pytest.mark.parametrize("allow_submission_customize", [True, False], ids=["submission_customize=true", "submission_customize=false"])
def test_set_user_settings(datastore, login_session, allow_submission_customize):
    _, session, host = login_session
    username = random.choice(user_list)
    user = datastore.user.get(username, as_obj=False)

    if allow_submission_customize:
        # User is allowed to customize their submission profiles
        datastore.user.update(username, [(datastore.user.UPDATE_APPEND, 'roles', 'submission_customize')])
        if 'submission_customize' not in user['roles']:
            user['roles'].append('submission_customize')
    else:
        # Users that aren't allow to customize submissions shouldn't be able to customize
        # submission profiles parameters if the configuration doesn't allow it
        datastore.user.update(username, [(datastore.user.UPDATE_REMOVE, 'roles', 'submission_customize')])
        if 'submission_customize' in user['roles']:
            user['roles'].remove('submission_customize')
    datastore.user.commit()

    uset = load_user_settings(user)

    # Ensure ignore_recursion_prevention is set within the user's profile for Static Analysis
    uset['submission_profiles']['static']['ignore_recursion_prevention'] = False

    # Initialize user profile settings with default values for comparison
    datastore.user_settings.update(username, [(datastore.user_settings.UPDATE_SET, 'submission_profiles', uset['submission_profiles'])])
    datastore.user_settings.commit()

    # Set some arbitrary values for the user settings to see if changes can be made
    uset['expand_min_score'] = 111
    uset['submission_profiles']['static']['priority'] = 111
    uset['submission_profiles']['static']['service_spec'] = {
        "APKaye": {
            "resubmit_apk_as_jar": True
        }
    }

    # Change a parameter that is defined restricted within the profile configuration
    uset['submission_profiles']['static']["ignore_recursion_prevention"] = True

    if allow_submission_customize:
        # User is allowed to customize their submission profiles as they see fit
        resp = get_api_data(session, f"{host}/api/v4/user/settings/{username}/", method="POST", data=json.dumps(uset))
        assert resp['success']

        datastore.user_settings.commit()
        new_user_settings = load_user_settings(user)

        # Ensure the changes are applied in the right places
        requested_profile_settings = uset['submission_profiles']['static']
        new_profile_setttings = new_user_settings['submission_profiles']['static']
        assert new_profile_setttings['priority'] == requested_profile_settings['priority']
        assert new_profile_setttings['service_spec'] == requested_profile_settings['service_spec']
    else:
        with pytest.raises(APIError,
                           match="User isn't allowed to modify the \"ignore_recursion_prevention\" parameters of Static Analysis profile"):
            # User isn't allowed to customize their submission profiles, API should return an exception
            resp = get_api_data(session, f"{host}/api/v4/user/settings/{username}/", method="POST", data=json.dumps(uset))
