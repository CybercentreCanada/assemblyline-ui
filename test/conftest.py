import os
import redis
import requests
import warnings

import pytest

from json import JSONDecodeError

from assemblyline.common import forge
from assemblyline.datastore.store import ESStore

original_classification = forge.get_classification


def test_classification(yml_config=None):
    """Patch the forge generation of classifications to use local test config."""
    path = os.path.join(os.path.dirname(__file__), 'config', 'classification.yml')
    return original_classification(path)


forge.get_classification = test_classification

# Must be imported AFTER the forge patch otherwise the correct classification yaml will not be picked up
from assemblyline_core.dispatching.schedules import Scheduler  # noqa
from assemblyline.datastore.helper import AssemblylineDatastore  # noqa


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


@pytest.fixture(scope='module')
def filestore(config):
    try:
        return forge.get_filestore(config, connection_attempts=1)
    except ConnectionError as err:
        pytest.skip(str(err))


# Under different test setups, the host may have a different address
POSSIBLE_HOSTS = [
    "https://localhost:443",
    "https://nginx",
]


class InvalidRequestMethod(Exception):
    pass


class APIError(Exception):
    pass


@pytest.fixture(scope='session')
def redis_connection(config):
    try:
        from assemblyline.remote.datatypes import get_client
        c = get_client(config.core.redis.nonpersistent.host, config.core.redis.nonpersistent.port, False)
        ret_val = c.ping()
        if ret_val:
            return c
    except redis.ConnectionError:
        pass

    pytest.skip("Connection to the Redis server failed. This test cannot be performed...")


@pytest.fixture(scope='module')
def scheduler(datastore_connection, config, redis_connection):
    return Scheduler(datastore_connection, config, redis_connection)


@pytest.fixture(scope='session')
def host(redis_connection):
    """Figure out what hostname will reach the api server.

    We also probe for the host so that we can fail faster when it is missing.
    Request redis first, because if it is missing, the ui server can hang.

    Try three times, in an outer loop, so we try the other urls while waiting
    for the failed address to become available.
    """
    errors = {}
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        for host in POSSIBLE_HOSTS:
            try:
                result = requests.get(f"{host}/api/v4/auth/login/", verify=False, timeout=5)
                if result.status_code == 401:
                    return host
                result.raise_for_status()
                errors[host] = str(result.status_code)
            except requests.RequestException as err:
                errors[host] = str(err)

    pytest.skip("Couldn't find the API server, can't test against it.\n" +
                '\n'.join(k + ' ' + v for k, v in errors.items()))


@pytest.fixture(scope='function')
def login_session(host):
    try:
        session = requests.Session()
        data = get_api_data(session, f"{host}/api/v4/auth/login/", params={'user': 'admin', 'password': 'admin'})
        return data, session, host
    except requests.ConnectionError as err:
        pytest.skip(str(err))


@pytest.fixture(scope='function')
def login_user_session(host):
    try:
        session = requests.Session()
        data = get_api_data(session, f"{host}/api/v4/auth/login/", params={'user': 'user', 'password': 'user'})
        return data, session, host
    except requests.ConnectionError as err:
        pytest.skip(str(err))

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
            res = session.delete(url, data=data, params=params, verify=False, headers=headers)
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
                try:
                    res_data = res.json()
                    return res_data['api_response']
                except Exception:
                    raise APIError(f'{res.status_code}: {res.content or None}')
            else:
                try:
                    res_data = res.json()
                    raise APIError(res_data["api_error_message"])
                except JSONDecodeError:
                    raise APIError(f'{res.status_code}: {res.content}')
