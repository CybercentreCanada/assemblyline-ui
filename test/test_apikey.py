import json
from assemblyline.odm.models.apikey import Apikey, get_apikey_id
import pytest
import random
import urllib.parse

from conftest import APIError, get_api_data

from assemblyline.common.forge import get_classification
from assemblyline.odm.models.user import ROLES, load_roles_form_acls
from assemblyline.odm.randomizer import random_model_obj
from assemblyline.odm.random_data import DEV_APIKEY_NAME, create_users, wipe_users


CLASSIFICATION = get_classification()
NUM_KEYS = 2
FAV_TYPES = ['alert', 'error', 'search', 'signature', 'submission']
user_list = ["user", "admin"]
apikey_list = [get_apikey_id(DEV_APIKEY_NAME, "admin"), get_apikey_id(DEV_APIKEY_NAME, "user")]

DEFAULT_ACL = ["R"]
DEFAULT_ROLES = [r for r in load_roles_form_acls(DEFAULT_ACL, [])]

@pytest.fixture(scope="module")
def datastore(datastore_connection):
    global apikey_list
    ds = datastore_connection

    try:
        create_users(ds)

        for x in user_list:
            for y in range(NUM_KEYS):
                key_name = f"testkey_{y+1}"
                key_data = random_model_obj(Apikey)
                key_id = get_apikey_id(key_name, x)
                key_data.uname = x
                key_data.key_name = key_name
                key_data.acl = DEFAULT_ACL
                key_data.roles = DEFAULT_ROLES

                ds.apikey.save(key_id, key_data)
                apikey_list.append(key_id)

        ds.apikey.commit()
        yield ds
    finally:
        wipe_users(ds)


# noinspection PyUnusedLocal
def test_apikey_list(datastore, login_session):
    user_info, session, host = login_session

    assert user_info['username'] == "admin"

    resp = get_api_data(session, f"{host}/api/v4/apikey/list/")
    assert resp["total"] == (len(apikey_list))

    for item in resp['items']:
        # make sure api is not returning password
        assert 'password' not in item.keys()

# noinspection PyUnusedLocal
def test_not_allowed_apikey_list(datastore, login_user_session):
    user_info , session, host = login_user_session

    assert user_info['username'] == "user"

    with pytest.raises(APIError):
        resp = get_api_data(session, f"{host}/api/v4/apikey/list/")

# noinspection PyUnusedLocal
def test_admin_get_apikey(datastore, login_session):
    _ , session, host = login_session


    # api should throw error for incorrect key_id
    with pytest.raises(APIError):
        resp = get_api_data(session, f"{host}/api/v4/apikey/wrongid/")

    # test if admin can access apikey of other use
    user_apikey_id = get_apikey_id(DEV_APIKEY_NAME, 'user')
    resp = get_api_data(session, f"{host}/api/v4/apikey/{user_apikey_id}/")
    assert resp['uname'] == "user"
    assert resp["key_name"] == DEV_APIKEY_NAME
    assert resp["id"] == user_apikey_id

# noinspection PyUnusedLocal
def test_get_apikey(datastore, login_user_session):
    user_info, session, host = login_user_session

    username = "user"

    assert user_info['username'] == username

    # user cannot access API key that does not belong to them
    with pytest.raises(APIError):
        admin_apikey_id = get_apikey_id(DEV_APIKEY_NAME, 'admin')
        resp = get_api_data(session, f"{host}/api/v4/apikey/{admin_apikey_id}/")

    # user can access their own apikey
    user_apikey_id = get_apikey_id(DEV_APIKEY_NAME, username)
    resp = get_api_data(session, f"{host}/api/v4/apikey/{user_apikey_id}/")

    assert resp['uname'] == username
    assert resp["key_name"] == DEV_APIKEY_NAME
    assert resp["id"] == user_apikey_id

# noinspection PyUnusedLocal
def test_add_apikey(datastore, login_user_session):
    user_info, session, host = login_user_session

    username = "user"

    assert user_info['username'] == username

    random_apikey = dict({
        "priv": ["W"],
        "id": apikey_list[0],
        "key_name": DEV_APIKEY_NAME
    })


    with pytest.raises(APIError):
        # duplicate keyname not allowed
        resp = get_api_data(session,  f"{host}/api/v4/apikey/add/?keyid={urllib.parse.quote_plus(apikey_list[0])}",
                            data=json.dumps(random_apikey), method="PUT")


    key_id = get_apikey_id(keyname=DEV_APIKEY_NAME, uname=username)
    random_apikey = dict({
        "priv": ["W"],
        "key_name": DEV_APIKEY_NAME,
        "uname": "wrong_person"
    })
    with pytest.raises(APIError):
        # cannot modify apikey that belongs to another uname if user is not admin
        resp = get_api_data(session,  f"{host}/api/v4/apikey/add/?keyid={urllib.parse.quote_plus(key_id)}",
                        data=json.dumps(random_apikey), method="PUT")


def test_admin_add_apikey(datastore, login_session):
    user_info, session, host = login_session

    username = "admin"
    assert user_info['username'] == username

    key_id = get_apikey_id(keyname=DEV_APIKEY_NAME, uname="user")

    random_apikey = dict({
        "priv": ["W"],
        "key_name": DEV_APIKEY_NAME,
        "uname": "user",
        "expiry_ts": None,
        "roles": [r for r in load_roles_form_acls(["W"], [])]
    })

    apikey = datastore.apikey.get(key_id, as_obj=False)
    old_password = apikey["password"]

    resp = get_api_data(session,  f"{host}/api/v4/apikey/add/?keyid={urllib.parse.quote_plus(key_id)}",
                            data=json.dumps(random_apikey), method="PUT")

    # make sure the api server is not leaking the password hash when modifying existing apikey
    assert resp['keypassword'] == None

    datastore.apikey.commit()

    apikey = datastore.apikey.get(key_id, as_obj=False)

    roles = set( [r for r in load_roles_form_acls(["W"], [])])

    # updating key should not update password
    assert old_password == apikey["password"]
    assert apikey["uname"] == "user"
    assert apikey["expiry_ts"] == None
    assert set(apikey["acl"]).issubset(set(["W"])) and set(apikey["acl"]).issuperset(set(["W"]))
    assert set(apikey["roles"]).issubset(roles) and set(apikey["roles"]).issuperset(roles)


    # make new key
    random_apikey = dict({
        "priv": ["W"],
        "key_name": "new_key+",
        "uname": "user",
        "expiry_ts": None,
        "roles": [r for r in load_roles_form_acls(["W"], [])]
    })

    with pytest.raises(APIError):
        # cannot make this new apikey becase key_name contains forbidden characters
        resp = get_api_data(session,  f"{host}/api/v4/apikey/add/",
                            data=json.dumps(random_apikey), method="PUT")

    # make new key
    random_apikey = dict({
        "priv": ["C"],
        "key_name": "new_key",
        "uname": "user",
        "expiry_ts": None,
        "roles": [ROLES.administration]
    })

    with pytest.raises(APIError):
        # cannot make this new apikey because user does not have the permission for the roles requested
        resp = get_api_data(session,  f"{host}/api/v4/apikey/add/",
                            data=json.dumps(random_apikey), method="PUT")

    # make new key
    random_apikey = dict({
        "priv": ["C"],
        "key_name": "new_key",
        "uname": "user",
        "expiry_ts": None,
        "roles": [ROLES.badlist_manage]
    })

    resp = get_api_data(session,  f"{host}/api/v4/apikey/add/",
                                data=json.dumps(random_apikey), method="PUT")
    datastore.apikey.commit()

    assert resp["keypassword"] is not None and len(resp["keypassword"].split(":")) >= 2
    assert resp["keypassword"].split(":")[0] == "new_key"

    key_id = get_apikey_id(keyname="new_key", uname="user")
    apikey = datastore.apikey.get(key_id, as_obj=False)

    roles = set([ROLES.badlist_manage])

    assert apikey["key_name"] == "new_key"
    assert apikey["uname"] == "user"
    assert apikey["expiry_ts"] == None
    assert set(apikey["acl"]).issubset(set(["C"])) and set(apikey["acl"]).issuperset(set(["C"]))
    assert set(apikey["roles"]).issubset(roles) and set(apikey["roles"]).issuperset(roles)



# noinspection PyUnusedLocal
def test_delete_apikey(datastore, login_user_session):
    user_info, session, host = login_user_session

    assert user_info['username'] == "user"

    key_id = get_apikey_id(keyname=DEV_APIKEY_NAME, uname="admin")
    resp = get_api_data(session,  f"{host}/api/v4/apikey/{urllib.parse.quote_plus(key_id)}/",
                    method="DELETE")

    datastore.apikey.commit()
    apikey = datastore.apikey.get(key_id, as_obj=False)

    assert not resp["success"]
    assert apikey is not None



# noinspection PyUnusedLocal
def test_admin_delete_apikey(datastore, login_session):
    user_info, session, host = login_session
    assert user_info['username'] == "admin"

    # admin is able to delete any apikey
    key_id = get_apikey_id(keyname=DEV_APIKEY_NAME, uname="user")

    resp = get_api_data(session,  f"{host}/api/v4/apikey/{urllib.parse.quote_plus(key_id)}/",
                    method="DELETE")

    datastore.apikey.commit()
    apikey = datastore.apikey.get(key_id)

    assert resp["success"]
    assert apikey == None

    # admin is able to delete any apikey
    key_id = get_apikey_id(keyname=DEV_APIKEY_NAME, uname="admin")
    resp = get_api_data(session,  f"{host}/api/v4/apikey/{urllib.parse.quote_plus(key_id)}/",
                    method="DELETE")

    datastore.apikey.commit()
    apikey = datastore.apikey.get(key_id)

    assert resp["success"]
    assert apikey == None

    key_id = get_apikey_id(keyname="does_not_exist", uname="admin")
    resp = get_api_data(session,  f"{host}/api/v4/apikey/{urllib.parse.quote_plus(key_id)}/",
                    method="DELETE")

    datastore.apikey.commit()
    apikey = datastore.apikey.get(key_id)

    assert not resp["success"]
    assert apikey == None
