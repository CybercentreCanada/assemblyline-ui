
import pytest
import requests
import warnings


from assemblyline.common.security import get_password_hash
from assemblyline.common.yara import YaraImporter
from assemblyline.odm.models.service import Service
from assemblyline.odm.models.user import User
from assemblyline.odm.models.user_settings import UserSettings
from assemblyline.odm.randomizer import SERVICES

HOST = "https://localhost:443"


class InvalidRequestMethod(Exception):
    pass


class APIError(Exception):
    pass

class NullLogger(object):
    def info(self, msg):
        pass

    def warn(self, msg):
        pass

    def error(self, msg):
        pass

    def exception(self, msg):
        pass

    def warning(self, msg):
        pass


def wipe_users(ds):
    ds.user.wipe()
    ds.user_settings.wipe()
    ds.user_avatar.wipe()
    ds.user_favorites.wipe()

def wipe_services(ds):
    ds.service.wipe()
    ds.service_delta.wipe()

def create_signatures():
    yp = YaraImporter(logger=NullLogger())
    parsed = yp.parse_file('al_yara_signatures.yar')
    yp.import_now([p['rule'] for p in parsed])
    return [p['rule']['name'] for p in parsed]

def create_users(ds):
    user_data = User({
        "agrees_with_tos": "NOW",
        "classification": "RESTRICTED",
        "name": "Admin user",
        "password": get_password_hash("admin"),
        "uname": "admin",
        "is_admin": True})
    ds.user.save('admin', user_data)
    ds.user_settings.save('admin', UserSettings())
    user_data = User({"name": "user", "password": get_password_hash("user"), "uname": "user"})
    ds.user.save('user', user_data)
    ds.user_settings.save('user', UserSettings())
    ds.user.commit()

def create_services(ds):
    for svc_name, svc in SERVICES.items():
        service_data = Service({
            "name": svc_name,
            "enabled": True,
            "category": svc[0],
            "stage": svc[1],
            "version": "3.3.0"
        })
        # Save a v3 service
        ds.service.save(f"{service_data.name}_{service_data.version}", service_data)

        # Save the same service as v4
        service_data.version = "4.0.0"
        ds.service.save(f"{service_data.name}_{service_data.version}", service_data)

        # Save the default delta entry
        ds.service_delta.save(service_data.name, {"version": service_data.version})
    ds.service_delta.commit()
    ds.service.commit()

@pytest.fixture(scope='function')
def login_session():
    session = requests.Session()
    data = get_api_data(session, f"{HOST}/api/v4/auth/login/", params={'user': 'admin', 'password': 'admin'})
    return data, session


def get_api_data(session, url, params=None, data=None, method="GET", raw=False):
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')

        if method == "GET":
            res = session.get(url, params=params, verify=False)
        elif method == "POST":
            res = session.post(url, data=data, params=params, verify=False,
                               headers={'content-type': 'application/json'})
        elif method == "DELETE":
            res = session.delete(url, params=params, verify=False)
        elif method == "PUT":
            res = session.put(url, data=data, params=params, verify=False,
                              headers={'content-type': 'application/json'})
        else:
            raise InvalidRequestMethod(method)

        if "XSRF-TOKEN" in res.cookies:
            session.headers.update({"X-XSRF-TOKEN": res.cookies['XSRF-TOKEN']})

        if raw:
            return res.content
        else:
            res_data = res.json()

            if res.ok:
                return res_data['api_response']
            else:
                raise APIError(res_data["api_error_message"])