import os
from json import JSONDecodeError

import requests
import warnings

import pytest

from assemblyline.common import forge
from assemblyline.datastore.helper import AssemblylineDatastore
from assemblyline.datastore.stores.es_store import ESStore

original_skip = pytest.skip

# Check if we are in an unattended build environment where skips won't be noticed
IN_CI_ENVIRONMENT = any(indicator in os.environ for indicator in
                        ['CI', 'BITBUCKET_BUILD_NUMBER', 'AGENT_JOBSTATUS'])


def skip_or_fail(message):
    """Skip or fail the current test, based on the environment"""
    if IN_CI_ENVIRONMENT:
        pytest.fail(message)
    else:
        original_skip(message)


# Replace the built in skip function with our own
pytest.skip = skip_or_fail


@pytest.fixture(scope='session')
def config():
    return forge.get_config()


@pytest.fixture(scope='module')
def datastore_connection(config):

    store = ESStore(config.datastore.hosts)
    ret_val = store.ping()
    if not ret_val:
        pytest.skip("Could not connect to datastore")

    return AssemblylineDatastore(store)


HOST = "https://localhost:443"


class InvalidRequestMethod(Exception):
    pass


class APIError(Exception):
    pass


@pytest.fixture(scope='function')
def login_session():
    session = requests.Session()
    data = get_api_data(session, f"{HOST}/api/v4/auth/login/", params={'user': 'admin', 'password': 'admin'})
    return data, session


def get_api_data(session, url, params=None, data=None, method="GET", raw=False, headers=None, files=None):

    if headers is None:
        headers = {'content-type': 'application/json'}

    with warnings.catch_warnings():
        warnings.simplefilter('ignore')

        if method == "GET":
            res = session.get(url, params=params, verify=False)
        elif method == "POST":
            res = session.post(url, data=data, params=params, verify=False, headers=headers, files=files)
        elif method == "DELETE":
            res = session.delete(url, data=data, params=params, verify=False)
        elif method == "PUT":
            res = session.put(url, data=data, params=params, verify=False, headers=headers, files=files)
        else:
            raise InvalidRequestMethod(method)

        if "XSRF-TOKEN" in res.cookies:
            session.headers.update({"X-XSRF-TOKEN": res.cookies['XSRF-TOKEN']})

        if raw:
            return res.content
        else:
            if res.ok:
                res_data = res.json()
                return res_data['api_response']
            else:
                try:
                    res_data = res.json()
                    raise APIError(res_data["api_error_message"])
                except JSONDecodeError:
                    raise APIError(f'{res.status_code}: {res.content}')

