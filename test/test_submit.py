import base64
import hashlib
import json
import os
import random
import tempfile
import time
from typing import Optional, Any, Iterable
from collections import defaultdict

import pytest
from assemblyline.datastore.helper import AssemblylineDatastore
from assemblyline.odm.models.submission import Submission
from assemblyline.odm.models.user import User

from assemblyline.common import forge
from assemblyline.datastore.collection import Index
from assemblyline.odm.models.config import DEFAULT_SRV_SEL, HASH_PATTERN_MAP, Config
from assemblyline.odm.models.service import Service
from assemblyline.odm.random_data import (
    create_services,
    create_submission,
    create_users,
    wipe_services,
    wipe_submissions,
    wipe_users,
)
from assemblyline.odm.randomizer import get_random_phrase, random_minimal_obj
from assemblyline.remote.datatypes.queues.named import NamedQueue
from conftest import APIError, get_api_data

config = forge.get_config()
sq = NamedQueue('dispatch-submission-queue', host=config.core.redis.persistent.host,
                port=config.core.redis.persistent.port)
submission = None


class TemporaryFileData:
    def __init__(self, *args, **kwargs) -> None:
        pass


class SubmissionTask:
    """Dispatcher internal model for submissions"""

    def __init__(
        self,
        submission,
        completed_queue,
        scheduler,
        datastore: AssemblylineDatastore,
        config: Config,
        results=None,
        file_infos=None,
        file_tree=None,
        errors: Optional[Iterable[str]] = None,
    ):
        self.submission: Submission = Submission(submission)
        submitter: Optional[User] = datastore.user.get_if_exists(self.submission.params.submitter)
        self.service_access_control: Optional[str] = None
        if submitter:
            self.service_access_control = submitter.classification.value

        self.completed_queue = None

        if completed_queue:
            self.completed_queue = str(completed_queue)

        self.file_info: dict[str, Optional[FileInfo]] = {}
        self.file_names: dict[str, str] = {}
        self.file_schedules: dict[str, list[dict[str, Service]]] = {}
        self.file_tags: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
        self.file_depth: dict[str, int] = {}
        self.temporary_data: dict[str, TemporaryFileData] = {}
        self.extra_errors: list[str] = []
        self.active_files: set[str] = set()
        self.dropped_files: set[str] = set()
        self.dynamic_recursion_bypass: set[str] = set()
        self.service_logs: dict[tuple[str, str], list[str]] = defaultdict(list)
        self.monitoring: dict[tuple[str, str], MonitorTask] = {}

        # mapping from file hash to a set of services that shouldn't be run on
        # any children (recursively) of that file
        self._forbidden_services: dict[str, set[str]] = {}
        self._parent_map: dict[str, set[str]] = {}

        self.service_results: dict[tuple[str, str], ResultSummary] = {}
        self.service_errors: dict[tuple[str, str], str] = {}
        self.service_attempts: dict[tuple[str, str], int] = defaultdict(int)
        self.queue_keys: dict[tuple[str, str], str] = {}
        self.running_services: set[tuple[str, str]] = set()

        if file_infos is not None:
            self.file_info.update({k: FileInfo(v) for k, v in file_infos.items()})

        if file_tree is not None:
            def recurse_tree(tree, depth):
                for sha256, file_data in tree.items():
                    self.file_depth[sha256] = depth
                    self.file_names[sha256] = file_data['name'][0]
                    recurse_tree(file_data['children'], depth + 1)

            recurse_tree(file_tree, 0)
            sorted_file_depth = [(k, v) for k, v in sorted(self.file_depth.items(), key=lambda fd: fd[1])]
        else:
            sorted_file_depth = [(self.submission.files[0].sha256, 0)]

        for sha256, depth in sorted_file_depth:
            # populate temporary data to root level files
            if depth == 0:
                # Apply initial data parameter
                temp_key_config = dict(config.submission.default_temporary_keys)
                temp_key_config.update(config.submission.temporary_keys)
                temporary_data = TemporaryFileData(sha256, config=temp_key_config)
                self.temporary_data[sha256] = temporary_data
                if self.submission.params.initial_data:
                    try:
                        for key, value in dict(json.loads(self.submission.params.initial_data)).items():
                            if len(str(value)) > config.submission.max_temp_data_length:
                                continue
                            temporary_data.set_value(key, value)

                    except (ValueError, TypeError):
                        pass

        if results is not None:
            rescan = scheduler.expand_categories(self.submission.params.services.rescan)
            result_keys = list(results.keys())

            # Replay the process of routing files for dispatcher internal state.
            for k, result in results.items():
                sha256, service, _ = k.split('.', 2)
                service = scheduler.services.get(service)
                if not service:
                    continue

                prevented_services = scheduler.expand_categories(service.recursion_prevention)

                for service_name in prevented_services:
                    self.forbid_for_children(sha256, service_name)

            # Replay the process of receiving results for dispatcher internal state
            # iterate through result based on file depth
            for sha256, depth in sorted_file_depth:
                results_to_process = list(filter(lambda k: sha256 in k, result_keys))
                for result_key in results_to_process:
                    result = results[result_key]
                    sha256, service, _ = result_key.split(".", 2)

                    if service not in rescan:
                        extracted = result["response"]["extracted"]
                        children: list[str] = [r["sha256"] for r in extracted]
                        self.register_children(sha256, children)
                        children_detail: list[tuple[str, str]] = [
                            (r["sha256"], r["parent_relation"]) for r in extracted
                        ]
                        self.service_results[(sha256, service)] = ResultSummary(
                            key=result_key,
                            drop=result["drop_file"],
                            score=result["result"]["score"],
                            children=children_detail,
                            partial=result.get("partial", False),
                        )

                    tags = Result(result).scored_tag_dict()
                    for key, tag in tags.items():
                        if key in self.file_tags[sha256].keys():
                            # Sum score of already known tags
                            self.file_tags[sha256][key]["score"] += tag["score"]
                        else:
                            self.file_tags[sha256][key] = tag

        if errors is not None:
            for e in errors:
                sha256, service, _ = e.split('.', 2)
                self.service_errors[(sha256, service)] = e

    @property
    def sid(self) -> str:
        """Shortcut to read submission SID"""
        return self.submission.sid


@pytest.fixture(scope="module")
def datastore(datastore_connection, filestore):
    global submission
    try:
        create_users(datastore_connection)
        submission = create_submission(datastore_connection, filestore)
        create_services(datastore_connection)
        yield datastore_connection
    finally:
        wipe_users(datastore_connection)
        wipe_submissions(datastore_connection, filestore)
        wipe_services(datastore_connection)
        sq.delete()


# noinspection PyUnusedLocal
@pytest.mark.parametrize("from_archive", [False, True], ids=["from_filestore", "from_archivestore"])
def test_resubmit(datastore, filestore, archivestore, login_session, scheduler, from_archive):
    _, session, host = login_session

    sq.delete()
    submission_files = [f.sha256 for f in submission.files]

    if from_archive:
        # Save file to archivestore and remove from filestore (let's pretend it was archived and expired from filestore)
        for sha256 in submission_files:
            archivestore.put(sha256, filestore.get(sha256))
            filestore.delete(sha256)
            datastore.file.archive(sha256)
            datastore.file.delete(sha256, index_type=Index.HOT)
        datastore.file.commit()

    resp = get_api_data(session, f"{host}/api/v4/submit/resubmit/{submission.sid}/")
    assert resp['params']['description'].startswith('Resubmit')
    assert resp['sid'] != submission.sid
    for f in resp['files']:
        assert f['sha256'] in submission_files
        assert filestore.exists(f['sha256'])

    msg = SubmissionTask(scheduler=scheduler, datastore=datastore, config=config, **sq.pop(blocking=False))
    assert msg.submission.sid == resp['sid']

# noinspection PyUnusedLocal
@pytest.mark.parametrize("copy_sid", [True, False])
def test_resubmit_profile(datastore, login_session, scheduler, copy_sid):
    # Re-submit a submission with a profile selected (classification of submission should be kept)
    _, session, host = login_session

    sq.delete()
    sha256 = random.choice(submission.results)[:64]

    # Submit file for resubmission with a profile selected
    resp = get_api_data(session, f"{host}/api/v4/submit/static/{sha256}/{f'?copy_sid={submission.sid}' if copy_sid else ''}", method="PUT")
    if copy_sid:
        # Classification of original submission should be kept
        assert resp['classification'] == submission.classification.value
    else:
        # Classification of file should be used for the submission
        assert resp['classification'] == datastore.file.get(sha256, as_obj=False)['classification']
    assert resp['params']['description'].startswith('Resubmit')
    assert resp['params']['description'].endswith('Static Analysis')
    assert resp['sid'] != submission.sid
    for f in resp['files']:
        assert f['sha256'] == sha256

    # Calculate the default selected services relative to the test deployment with mock data
    default_selected_services = set(DEFAULT_SRV_SEL) | set(datastore.service.facet("category").keys()) \
        - {"Dynamic Analysis", "External"}

    assert set(resp['params']['services']['selected']) == default_selected_services

    msg = SubmissionTask(scheduler=scheduler, datastore=datastore, config=config, **sq.pop(blocking=False))
    assert msg.submission.sid == resp['sid']


# noinspection PyUnusedLocal
def test_resubmit_dynamic(datastore, login_session, scheduler):
    _, session, host = login_session

    sq.delete()
    sha256 = random.choice(submission.results)[:64]
    resp = get_api_data(session, f"{host}/api/v4/submit/dynamic/{sha256}/")
    assert resp['params']['description'].startswith('Resubmit')
    assert resp['params']['description'].endswith('Dynamic Analysis')
    assert resp['sid'] != submission.sid
    for f in resp['files']:
        assert f['sha256'] == sha256
    assert 'Dynamic Analysis' in resp['params']['services']['selected']

    msg = SubmissionTask(scheduler=scheduler, datastore=datastore, config=config, **sq.pop(blocking=False))
    assert msg.submission.sid == resp['sid']


# noinspection PyUnusedLocal
@pytest.mark.parametrize("hash", list(HASH_PATTERN_MAP.keys()))
def test_submit_hash(datastore, login_session, scheduler, hash, filestore):
    _, session, host = login_session

    sq.delete()
    # Look for any file where the hash of that file is set
    fileinfo = get_api_data(session, f"{host}/api/v4/search/file/?query=*&fl=sha256,{hash}&rows=1")['items'][0]

    data = {
        hash: fileinfo[hash],
        'name': 'random_hash.txt',
        'metadata': {'test': 'test_submit_hash'}
    }
    resp = get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=json.dumps(data))
    assert isinstance(resp['sid'], str)
    for f in resp['files']:
        assert f['sha256'] == fileinfo['sha256']
        assert f['name'] == data['name']

    msg = SubmissionTask(scheduler=scheduler, datastore=datastore, config=config, **sq.pop(blocking=False))
    assert msg.submission.sid == resp['sid']

# noinspection PyUnusedLocal
def test_submit_url(datastore, login_session, scheduler):
    _, session, host = login_session

    sq.delete()
    data = {
        'url': 'https://raw.githubusercontent.com/CybercentreCanada/assemblyline-ui/master/README.md',
        'name': 'README.md',
        'metadata': {'test': 'test_submit_url'}
    }
    resp = get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=json.dumps(data))
    assert isinstance(resp['sid'], str)
    for f in resp['files']:
        assert f['name'] == data['url']  # The name is overwritten for URIs

    msg = SubmissionTask(scheduler=scheduler, datastore=datastore, config=config, **sq.pop(blocking=False))
    assert msg.submission.sid == resp['sid']

# noinspection PyUnusedLocal
def test_submit_defanged_url(datastore, login_session, scheduler):
    _, session, host = login_session

    sq.delete()
    data = {
        'url': 'hxxps://raw[.]githubusercontent[.]com/CybercentreCanada/assemblyline-ui/master/README[.]md',
        'name': 'README.md',
        'metadata': {'test': 'test_submit_url'}
    }
    resp = get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=json.dumps(data))
    assert isinstance(resp['sid'], str)
    for f in resp['files']:
        # The name is overwritten for URIs
        assert f['name'] == 'https://raw.githubusercontent.com/CybercentreCanada/assemblyline-ui/master/README.md'

    msg = SubmissionTask(scheduler=scheduler, datastore=datastore, config=config, **sq.pop(blocking=False))
    assert msg.submission.sid == resp['sid']


# noinspection PyUnusedLocal
def test_submit_binary(datastore, login_session, scheduler):
    _, session, host = login_session

    sq.delete()
    byte_str = get_random_phrase(wmin=30, wmax=75).encode()
    fd, temp_path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, 'wb') as fh:
            fh.write(byte_str)

        with open(temp_path, 'rb') as fh:
            sha256 = hashlib.sha256(byte_str).hexdigest()
            json_data = {
                'name': 'binary.txt',
                'metadata': {'test': 'test_submit_binary'}
            }
            data = {'json': json.dumps(json_data)}
            resp = get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=data,
                                files={'bin': fh}, headers={})

        assert isinstance(resp['sid'], str)
        for f in resp['files']:
            assert f['sha256'] == sha256
            assert f['name'] == json_data['name']

        msg = SubmissionTask(scheduler=scheduler, datastore=datastore, config=config, **sq.pop(blocking=False))
        assert msg.submission.sid == resp['sid']

    finally:
        # noinspection PyBroadException
        try:
            os.unlink(temp_path)
        except Exception:
            pass


@pytest.mark.parametrize("filename", [None, "binary.txt", "./binary.txt"])
# noinspection PyUnusedLocal
def test_submit_binary_different_filename(datastore, login_session, scheduler, filename):
    _, session, host = login_session

    sq.delete()
    byte_str = get_random_phrase(wmin=30, wmax=75).encode()
    fd, temp_path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(byte_str)

        with open(temp_path, "rb") as fh:
            sha256 = hashlib.sha256(byte_str).hexdigest()
            json_data = {"metadata": {"test": "test_submit_binary"}}
            if filename:
                json_data["name"] = filename
            data = {"json": json.dumps(json_data)}

            resp = get_api_data(
                session, f"{host}/api/v4/submit/", method="POST", data=data, files={"bin": fh}, headers={}
            )

        assert isinstance(resp["sid"], str)
        for f in resp["files"]:
            assert f["sha256"] == sha256

            if filename:
                assert f["name"] == json_data["name"]
            else:
                assert f["name"] == os.path.basename(temp_path)

    finally:
        # noinspection PyBroadException
        try:
            os.unlink(temp_path)
        except Exception:
            pass


# noinspection PyUnusedLocal
def test_submit_binary_nameless(datastore, login_session, scheduler):
    _, session, host = login_session

    sq.delete()
    byte_str = get_random_phrase(wmin=30, wmax=75).encode()
    fd, temp_path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, 'wb') as fh:
            fh.write(byte_str)

        with open(temp_path, 'rb') as fh:
            sha256 = hashlib.sha256(byte_str).hexdigest()
            json_data = {
                'metadata': {'test': 'test_submit_binary_nameless'}
            }
            data = {'json': json.dumps(json_data)}
            resp = get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=data,
                                files={'bin': fh}, headers={})

        assert isinstance(resp['sid'], str)
        for f in resp['files']:
            assert f['sha256'] == sha256
            assert f['name'] == os.path.basename(temp_path)

        msg = SubmissionTask(scheduler=scheduler, datastore=datastore, config=config, **sq.pop(blocking=False))
        assert msg.submission.sid == resp['sid']

    finally:
        # noinspection PyBroadException
        try:
            os.unlink(temp_path)
        except Exception:
            pass


# noinspection PyUnusedLocal
def test_submit_plaintext(datastore, login_session, scheduler):
    _, session, host = login_session

    sq.delete()
    plain_str = get_random_phrase(wmin=30, wmax=75)
    sha256 = hashlib.sha256(plain_str.encode()).hexdigest()
    data = {
        'name': 'plain.txt',
        'plaintext': plain_str,
        'metadata': {'test': 'test_submit_plaintext'}
    }
    resp = get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=json.dumps(data))
    assert isinstance(resp['sid'], str)
    for f in resp['files']:
        assert f['sha256'] == sha256
        assert f['name'] == data['name']

    msg = SubmissionTask(scheduler=scheduler, datastore=datastore, config=config, **sq.pop(blocking=False))
    assert msg.submission.sid == resp['sid']


# noinspection PyUnusedLocal
def test_submit_plaintext_nameless(datastore, login_session, scheduler):
    _, session, host = login_session

    sq.delete()
    plain_str = get_random_phrase(wmin=30, wmax=75)
    sha256 = hashlib.sha256(plain_str.encode()).hexdigest()
    data = {
        'plaintext': plain_str,
        'metadata': {'test': 'test_submit_plaintext_nameless'}
    }
    resp = get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=json.dumps(data))
    assert isinstance(resp['sid'], str)
    for f in resp['files']:
        assert f['sha256'] == sha256
        assert f['name'] == sha256

    msg = SubmissionTask(scheduler=scheduler, datastore=datastore, config=config, **sq.pop(blocking=False))
    assert msg.submission.sid == resp['sid']


# noinspection PyUnusedLocal
def test_submit_base64(datastore, login_session, scheduler):
    _, session, host = login_session

    sq.delete()
    byte_str = get_random_phrase(wmin=30, wmax=75).encode()
    sha256 = hashlib.sha256(byte_str).hexdigest()
    data = {
        'name': 'base64.txt',
        'base64': base64.b64encode(byte_str).decode('ascii'),
        'metadata': {'test': 'test_submit_base64'}
    }
    resp = get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=json.dumps(data))
    assert isinstance(resp['sid'], str)
    for f in resp['files']:
        assert f['sha256'] == sha256
        assert f['name'] == data['name']

    msg = SubmissionTask(scheduler=scheduler, datastore=datastore, config=config, **sq.pop(blocking=False))
    assert msg.submission.sid == resp['sid']

# noinspection PyUnusedLocal
def test_submit_base64_nameless(datastore, login_session, scheduler):
    _, session, host = login_session

    sq.delete()
    byte_str = get_random_phrase(wmin=30, wmax=75).encode()
    sha256 = hashlib.sha256(byte_str).hexdigest()
    data = {
        'base64': base64.b64encode(byte_str).decode('ascii'),
        'metadata': {'test': 'test_submit_base64_nameless'}
    }
    resp = get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=json.dumps(data))
    assert isinstance(resp['sid'], str)
    for f in resp['files']:
        assert f['sha256'] == sha256
        assert f['name'] == sha256

    msg = SubmissionTask(scheduler=scheduler, datastore=datastore, config=config, **sq.pop(blocking=False))
    assert msg.submission.sid == resp['sid']

@pytest.mark.parametrize("submission_customize", [True, False], ids=["submission_customize_enabled", "submission_customize_disabled"])
def test_submit_submission_profile(datastore, login_session, scheduler, submission_customize):
    _, session, host = login_session
    sq.delete()

    # Make the user a simple user and try to submit
    if not submission_customize:
        datastore.user.update('admin', [
            (datastore.user.UPDATE_REMOVE, 'type', 'admin'),
            (datastore.user.UPDATE_APPEND, 'roles', 'submission_create')])
    byte_str = get_random_phrase(wmin=30, wmax=75).encode()
    data = {
        'base64': base64.b64encode(byte_str).decode('ascii'),
        'metadata': {'test': 'test_submit_base64_nameless'}
    }
    if submission_customize:
        # Users with submission customization enabled can submit without a profile specified
        resp = get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=json.dumps(data))

        # This should correspond with the submission parameters defined in the default submission profile
        submission_profile_data = get_api_data(session, f"{host}/api/v4/user/submission_params/{_['username']}/default/")
        for key, value in submission_profile_data.items():
            if key == "services":
                # Service selection should be the same
                for k, v in value.items():
                    assert set(v) == set(resp['params'][key][k])
            else:
                # All other parameters should match
                assert resp['params'][key] == value
    else:
        with pytest.raises(APIError, match="You must specify a submission profile"):
            # A basic user must specify a submission profile name
            get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=json.dumps(data))

        # Attempt to submission using a default submission profile
        data['submission_profile'] = "default"
        with pytest.raises(APIError, match="Submission profile 'default' does not exist"):
            get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=json.dumps(data))

    # Try using a submission profile with no parameters
    data['submission_profile'] = "static"
    submission = get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=json.dumps(data))

    # Ensure submission created has expected properties of using the submission profile
    submission_profile_data = get_api_data(session, f"{host}/api/v4/user/submission_params/{_['username']}/static/")
    selected_service_categories = set(datastore.service.facet("category").keys()) - {'Dynamic Analysis', 'External'}
    for key, value in submission_profile_data.items():
        if key == "services":
            # Ensure selected services are confined to the set of service categories present in the test
            assert selected_service_categories.issubset(set(submission['params']['services']['selected'])), f"{selected_service_categories} <= {set(submission['params']['services']['selected'])}"

            # Ensure Dynamic Analysis services are not selected
            assert submission_profile_data['services']['excluded'] == value['excluded'] == ['Dynamic Analysis']
        else:
            assert submission['params'][key] == value

    # Try using a submission profile with a parameter you aren't allowed to set
    if not datastore.service.search('category:"Dynamic Analysis"', rows=0, track_total_hits=True)['total']:
        # If there are no dynamic analysis services, add one
        service = random_minimal_obj(Service, as_json=True)
        service['name'] = "TestService"
        service['enabled'] = True
        service['category'] = 'Dynamic Analysis'
        datastore.service.save(f"{service['name']}_{service['version']}", service)
        datastore.service_delta.save(service['name'], {"version": service["version"]})
        datastore.service.commit()
        datastore.service_delta.commit()

        # Wait for the API to update it's service list cache
        time.sleep(60)

    data['params'] = {'services': {'selected': ['Dynamic Analysis']}}
    if not submission_customize:
        # Users without submission customization enabled cannot select services from the "Dynamic Analysis" category
        with pytest.raises(APIError, match='User isn\'t allowed to select the \\w+ service of "Dynamic Analysis" in "Static Analysis" profile'):
            get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=json.dumps(data))
    else:
        # Users with submission customization enabled can select services from any category they'd like
        get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=json.dumps(data))

    # Try setting a parameter that you are allowed to set
    data['params'] = {
        'deep_scan': True,
        'services': {
            'excluded': ['Antivirus']
        }
    }

    resp = get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=json.dumps(data))
    assert resp['params']['deep_scan']
    assert 'Antivirus' in resp['params']['services']['excluded']

    if not submission_customize:
        # Restore original roles for later tests
        datastore.user.update('admin', [(datastore.user.UPDATE_APPEND, 'type', 'admin'),])


def test_submit_default_metadata(datastore, login_session):
    _, session, host = login_session

    # Set some default metadata for the user
    default_metadata = {
        'default_key1': 'default_value1',
        'default_key2': 'default_value2'
    }
    datastore.user_settings.save('admin', {'default_metadata': default_metadata})

    byte_str = get_random_phrase(wmin=30, wmax=75).encode()
    data = {
        'base64': base64.b64encode(byte_str).decode('ascii'),
        'metadata': {'test': 'test_submit_base64_nameless'},
        'submission_profile': 'static'
    }

    resp = get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=json.dumps(data))

    # Ensure that the submission metadata contains both the default metadata and the submission provided metadata
    assert resp['metadata'] == default_metadata | data['metadata']
    assert len(resp['metadata']) == 3

    # Users should be able to override default metadata values by specifying them in the submission metadata
    data['metadata']['default_key1'] = 'overridden_value1'
    resp = get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=json.dumps(data))

    assert resp['metadata'] == default_metadata | data['metadata']
    assert resp['metadata']['default_key1'] == 'overridden_value1'

# noinspection PyUnusedLocal
def test_submit_service_parameter(datastore, login_session, scheduler):
    _, session, host = login_session
    byte_str = get_random_phrase(wmin=30, wmax=75).encode()
    data = {}
    data["base64"] = base64.b64encode(byte_str).decode("ascii")
    data["submission_profile"] = "static"
    data["params"] = {"services": {"selected": ["Extract"]}, "service_spec": {"Extract": {"password": "test_password"}}}
    resp = get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=json.dumps(data))

    datastore.submission.commit()
    submission = datastore.submission.get(resp["sid"])
    submission_params = submission["params"]

    assert "Extract" in submission_params["service_spec"]
    assert submission_params["service_spec"]["Extract"]["password"] == "test_password"

    # check that empty string password still gets stored in database
    data["params"] = {"services": {"selected": ["Extract"]}, "service_spec": {"Extract": {"password": ""}}}
    resp = get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=json.dumps(data))

    datastore.submission.commit()
    submission = datastore.submission.get(resp["sid"])
    submission_params = submission["params"]

    assert "Extract" in submission_params["service_spec"]
    assert submission_params["service_spec"]["Extract"]["password"] == ""
