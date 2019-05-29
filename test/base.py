import hashlib
import os
import random
from json import JSONDecodeError

import pytest
import requests
import warnings


from assemblyline.common.security import get_password_hash
from assemblyline.common.yara import YaraImporter
from assemblyline.odm.models.emptyresult import EmptyResult
from assemblyline.odm.models.error import Error
from assemblyline.odm.models.file import File
from assemblyline.odm.models.result import Result
from assemblyline.odm.models.service import Service
from assemblyline.odm.models.submission import Submission
from assemblyline.odm.models.user import User
from assemblyline.odm.models.user_settings import UserSettings
from assemblyline.odm.randomizer import SERVICES, random_model_obj, get_random_phrase

HOST = "https://localhost:443"
full_file_list = []


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


def wipe_submissions(ds, fs):
    ds.error.wipe()
    ds.file.wipe()
    ds.result.wipe()
    ds.submission.wipe()
    ds.submission_tags.wipe()
    ds.submission_tree.wipe()

    for f in full_file_list:
        fs.delete(f)


def get_sig_path():
    for (d, _, filenames) in os.walk('.'):
        for f in filenames:
            if f == 'al_yara_signatures.yar':
                return os.path.join(d, f)

    raise Exception('Could not find test yara files...')


def create_signatures():
    yp = YaraImporter(logger=NullLogger())
    parsed = yp.parse_file(get_sig_path())
    yp.import_now([p['rule'] for p in parsed])
    return [p['rule']['name'] for p in parsed]


def create_users(ds, log=None):
    user_data = User({
        "agrees_with_tos": "NOW",
        "classification": "RESTRICTED",
        "name": "Admin user",
        "password": get_password_hash("admin"),
        "uname": "admin",
        "is_admin": True})
    ds.user.save('admin', user_data)
    ds.user_settings.save('admin', UserSettings())
    if log:
        log.info(f"\tU:{user_data.uname}   P:{user_data.uname}")

    user_data = User({"name": "user", "password": get_password_hash("user"), "uname": "user"})
    ds.user.save('user', user_data)
    ds.user_settings.save('user', UserSettings())
    if log:
        log.info(f"\tU:{user_data.uname}   P:{user_data.uname}")

    ds.user.commit()


def create_services(ds, log=None):
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
        if log:
            log.info(f'\t{svc_name}')
    ds.service_delta.commit()
    ds.service.commit()


def create_errors_for_file(ds, f, services_done, log=None):
    e_list = []
    for _ in range(random.randint(0, 1)):
        e = random_model_obj(Error)

        # Only one error per service per file
        while e.response.service_name in services_done:
            e.response.service_name = random.choice(list(SERVICES.keys()))
        services_done.append(e.response.service_name)

        # Set the sha256
        e.sha256 = f

        e_key = e.build_key()
        e_list.append(e_key)
        if log:
            log.info(f"\t\t\t{e_key}")
        ds.error.save(e_key, e)

    return e_list


def create_results_for_file(ds, f, possible_childs=None, log=None):
    r_list = []
    services_done = []
    for _ in range(random.randint(2, 5)):
        r = random_model_obj(Result)
        # Only one result per service per file
        while r.response.service_name in services_done:
            r.response.service_name = random.choice(list(SERVICES.keys()))
        services_done.append(r.response.service_name)

        # Set the sha256
        r.sha256 = f

        if random.randint(1, 10) > 8:
            # Generate and empty result
            r_key = f"{r.build_key()}.e"
            ds.emptyresult.save(r_key, random_model_obj(EmptyResult))
        else:
            r_key = r.build_key()
            # Set random extracted files that are not top level
            if not possible_childs:
                r.response.extracted = []
            else:
                for e in r.response.extracted:
                    e.sha256 = random.choice(possible_childs)

            # Set random supplementary files that are not top level
            if not possible_childs:
                r.response.supplementary = []
            else:
                for s in r.response.supplementary:
                    s.sha256 = random.choice(possible_childs)
            ds.result.save(r_key, r)


        if log:
            log.info(f"\t\t\t{r_key}")
        r_list.append(r_key)

    return r_list


def create_submission(ds, fs, log=None):
    f_list = []
    r_list = []
    e_list = []

    first_level_files = []
    s = random_model_obj(Submission)

    if log:
        log.info(f"\t{s.sid}")
        log.info(f"\tGenerating files for submission...")
    for _ in range(random.randint(4, 8)):
        f = random_model_obj(File)
        byte_str = get_random_phrase(wmin=8, wmax=20).encode()
        sha256 = hashlib.sha256(byte_str).hexdigest()
        f.sha256 = sha256
        ds.file.save(sha256, f)
        fs.put(sha256, byte_str)

        if log:
            log.info(f"\t\t{sha256}")

        f_list.append(sha256)

    for _ in range(random.randint(1, 2)):
        first_level_files.append(f_list.pop())

    if log:
        log.info(f"\t\tGenerating results and errors for top level files...")
    for f in first_level_files:
        r_list.extend(create_results_for_file(ds, f, possible_childs=f_list, log=log))
        e_list.extend(create_errors_for_file(ds, f, [x.split('.')[1] for x in r_list if x.startswith(f)], log=log))

    if log:
        log.info(f"\t\tGenerating results and errors for children files...")
    for f in f_list:
        r_list.extend(create_results_for_file(ds, f, log=log))
        e_list.extend(create_errors_for_file(ds, f, [x.split('.')[1] for x in r_list if x.startswith(f)], log=log))

    s.results = r_list
    s.errors = e_list

    s.error_count = len(e_list)
    s.file_count = len({x[:64] for x in r_list})

    s.files = s.files[:len(first_level_files)]

    fid = 0
    for f in s.files:
        f.sha256 = first_level_files[fid]
        fid += 1

    ds.submission.save(s.sid, s)

    return s


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

