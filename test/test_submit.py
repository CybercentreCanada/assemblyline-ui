import base64
import hashlib
import json
import os
import random
import tempfile
import time

import pytest

from assemblyline.common import forge
from assemblyline.datastore.collection import Index
from assemblyline.odm.models.config import DEFAULT_SRV_SEL, HASH_PATTERN_MAP
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
from assemblyline_core.dispatching.dispatcher import SubmissionTask
from conftest import APIError, get_api_data

config = forge.get_config()
sq = NamedQueue('dispatch-submission-queue', host=config.core.redis.persistent.host,
                port=config.core.redis.persistent.port)
submission = None


class SubmissionTask:
    """Dispatcher internal model for submissions"""

    def __init__(self, submission, completed_queue, scheduler, datastore: AssemblylineDatastore, results=None,
                 file_infos=None, file_tree=None, errors: Optional[Iterable[str]] = None):
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

        if results is not None:
            rescan = scheduler.expand_categories(self.submission.params.services.rescan)

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
            for k, result in results.items():
                sha256, service, _ = k.split('.', 2)
                if service not in rescan:
                    extracted = result['response']['extracted']
                    children: list[str] = [r['sha256'] for r in extracted]
                    self.register_children(sha256, children)
                    children_detail: list[tuple[str, str]] = [(r['sha256'], r['parent_relation']) for r in extracted]
                    self.service_results[(sha256, service)] = ResultSummary(
                        key=k, drop=result['drop_file'], score=result['result']['score'],
                        children=children_detail, partial=result.get('partial', False))

                tags = Result(result).scored_tag_dict()
                for key, tag in tags.items():
                    if key in self.file_tags[sha256].keys():
                        # Sum score of already known tags
                        self.file_tags[sha256][key]['score'] += tag['score']
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

    def trace(self, event_type: str, sha256: Optional[str] = None,
              service: Optional[str] = None, message: Optional[str] = None) -> None:
        if self.submission.params.trace:
            self.submission.tracing_events.append(TraceEvent({
                'event_type': event_type,
                'service': service,
                'file': sha256,
                'message': message,
            }))

    def forbid_for_children(self, sha256: str, service_name: str):
        """Mark that children of a given file should not be routed to a service."""
        try:
            self._forbidden_services[sha256].add(service_name)
        except KeyError:
            self._forbidden_services[sha256] = {service_name}

    def register_children(self, parent: str, children: list[str]):
        """
        Note which files extracted other files.
        _parent_map is for dynamic recursion prevention
        temporary_data is for cascading the temp data to children
        """
        parent_temp = self.temporary_data[parent]
        for child in children:
            if child not in self.temporary_data:
                self.temporary_data[child] = parent_temp.new_file(child)
            try:
                self._parent_map[child].add(parent)
            except KeyError:
                self._parent_map[child] = {parent}

    def all_ancestors(self, sha256: str) -> list[str]:
        """Collect all the known ancestors of the given file within this submission."""
        visited = set()
        to_visit = [sha256]
        while len(to_visit) > 0:
            current = to_visit.pop()
            for parent in self._parent_map.get(current, []):
                if parent not in visited:
                    visited.add(parent)
                    to_visit.append(parent)
        return list(visited)

    def find_recursion_excluded_services(self, sha256: str) -> list[str]:
        """
        Return a list of services that should be excluded for the given file.

        Note that this is computed dynamically from the parent map every time it is
        called. This is to account for out of order result collection in unusual
        circumstances like replay.
        """
        return list(set().union(*[
            self._forbidden_services.get(parent, set())
            for parent in self.all_ancestors(sha256)
        ]))

    def set_monitoring_entry(self, sha256: str, service_name: str, values: dict[str, Optional[str]]):
        """A service with monitoring has dispatched, keep track of the conditions."""
        self.monitoring[(sha256, service_name)] = MonitorTask(
            service=service_name,
            sha=sha256,
            values=values,
        )

    def partial_result(self, sha256, service_name) -> bool:
        """Note that a partial result has been recieved. If a dispatch was requested process that now."""
        try:
            entry = self.monitoring[(sha256, service_name)]
        except KeyError:
            return False

        if entry.dispatch_needed:
            self.redispatch_service(sha256, service_name)
            return True
        return False

    def clear_monitoring_entry(self, sha256, service_name):
        """A service has completed normally. If the service is monitoring clear out the record."""
        # We have an incoming non-partial result, flush out any partial monitoring
        self.monitoring.pop((sha256, service_name), None)
        # If there is a partial result for this service flush that as well so we accept this new result
        result = self.service_results.get((sha256, service_name))
        if result and result.partial:
            self.service_results.pop((sha256, service_name), None)

    def temporary_data_changed(self, key: str) -> list[str]:
        """Check all of the monitored tasks on that key for changes. Redispatch as needed."""
        changed = []
        for (sha256, service), entry in self.monitoring.items():
            # Check if this key is actually being monitored by this entry
            if key not in entry.values:
                continue

            # Get whatever values (if any) were provided on the previous dispatch of this service
            value = self.temporary_data[sha256].read_key(key)
            dispatched_value = entry.values.get(key)

            if type(value) is not type(dispatched_value) or value != dispatched_value:
                result = self.service_results.get((sha256, service))
                if not result:
                    # If the value has changed since the last dispatch but results haven't come in yet
                    # mark this service to be disptached later. This will only happen if the service
                    # returns partial results, if there are full results the entry will be cleared instead.
                    entry.dispatch_needed = True
                else:
                    # If there are results and there is a monitoring entry, the result was partial
                    # so redispatch it immediately. If there are not partial results the monitoring
                    # entry will have been cleared.
                    self.redispatch_service(sha256, service)
                    changed.append(sha256)
        return changed

    def redispatch_service(self, sha256, service_name):
        # Clear the result if its partial or an error
        result = self.service_results.get((sha256, service_name))
        if result and not result.partial:
            return
        self.service_results.pop((sha256, service_name), None)
        self.service_errors.pop((sha256, service_name), None)
        self.service_attempts[(sha256, service_name)] = 1

        # Try to get the service to run again by reseting the schedule for that service
        self.file_schedules.pop(sha256, None)


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
            assert selected_service_categories.issubset(set(submission['params']['services']['selected']))

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
        with pytest.raises(APIError, match='User isn\'t allowed to select the \w+ service of "Dynamic Analysis" in "Static Analysis" profile'):
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
