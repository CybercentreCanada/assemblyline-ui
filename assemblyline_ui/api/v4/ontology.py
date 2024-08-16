import json

from flask import request
from io import StringIO

from assemblyline.common.dict_utils import recursive_update
from assemblyline.datastore.exceptions import MultiKeyError
from assemblyline.odm.models.user import ROLES
from assemblyline_ui.api.base import api_login, make_api_response, make_file_response, make_subapi_blueprint
from assemblyline_ui.config import ARCHIVESTORE, STORAGE, LOGGER, FILESTORE, CLASSIFICATION as Classification, config

SUB_API = 'ontology'
ontology_api = make_subapi_blueprint(SUB_API, api_version=4)
ontology_api._doc = "Download ontology results from the system"


def generate_ontology_file(results, user, updates={}, fnames={}):
    # Load ontology files
    sio = StringIO()

    # Start downloading all ontology files
    for r in results:
        for supp in r.get('response', {}).get('supplementary', {}):
            if supp['name'].endswith('.ontology'):

                # get ontology data
                ontology_data = FILESTORE.get(supp['sha256'])
                # Try to download from archive
                if not ontology_data and \
                        ARCHIVESTORE is not None and \
                        ARCHIVESTORE != FILESTORE and \
                        ROLES.archive_download in user['roles']:
                    ontology_data = ARCHIVESTORE.get(supp['sha256'])

                if not ontology_data:
                    # Could not download the ontology supplementary file
                    LOGGER.warning(f"Ontology file was not found filestores: {supp['name']} [{supp['sha256']}]")
                    continue

                try:
                    # Parse the ontology file
                    ontology = json.loads(ontology_data)
                    sha256 = ontology['file']['sha256']
                    c12n = ontology['classification']
                    if sha256 == r['sha256'] and Classification.is_accessible(user['classification'], c12n):
                        # Recursively update the ontology with the live values
                        ontology = recursive_update(ontology, updates)

                        # Set filenames if any
                        if sha256 in fnames:
                            ontology['file']['names'] = fnames[sha256]
                        elif 'names' in ontology['file']:
                            del ontology['file']['names']

                        # Make sure parent is not equal to current hash
                        if 'parent' in ontology['file'] and ontology['file']['parent'] == sha256:
                            del ontology['file']['parent']

                        # Ensure SHA256 is set in final output
                        ontology['file']['sha256'] = sha256

                        # Aggregated file score related to the results
                        ontology.setdefault('results', {})

                        # If the score hasn't already been assigned, then assign it based on result score
                        if 'score' not in ontology['results']:
                            ontology['results']['score'] = r['result']['score']

                        sio.write(json.dumps(ontology, indent=None, separators=(',', ':')) + '\n')
                except Exception as e:
                    LOGGER.warning(f"An error occured while parsing ontology files: {str(e)}")

    # Flush and reset buffer
    sio.flush()

    return sio


@ontology_api.route("/alert/<alert_id>/", methods=["GET"])
@api_login(require_role=[ROLES.alert_view])
def get_ontology_for_alert(alert_id, **kwargs):
    """
    WARNING:
        This APIs output is considered stable but the ontology model itself is still in its
        alpha state. Do not use the results of this API in a production system just yet.

    Get all ontology files for a given alert

    Variables:
    alert_id         => Alert ID to get ontology files for

    Arguments:
    sha256      => Only get ontology files for this file, multiple values allowed (optional)
    service     => Only get ontology files for this service, multiple values allowed (optional)

    Data Block:
    None

    Result example:      (File where each line is a result ontology record)
    {"header":{"md5":"5fa76...submitter":"admin"}}
    {"header":{"md5":"6c3af...submitter":"admin"}}
    {"header":{"md5":"c8e69...submitter":"admin"}}
    """
    user = kwargs['user']
    sha256s = request.args.getlist('sha256', None)
    services = request.args.getlist('service', None)

    # Get alert from ID
    alert = STORAGE.alert.get(alert_id, as_obj=False)
    if not alert:
        return make_api_response("", f"There is no alert with this ID: {alert_id}", 404)
    if not Classification.is_accessible(user['classification'], alert['classification']):
        return make_api_response("", f"You are not allowed get ontology files for this alert: {alert_id}", 403)

    # Get related submission
    submission = STORAGE.submission.get(alert['sid'], as_obj=False)
    if not submission:
        return make_api_response("", f"The submission related to the alert is missing: {alert_id}", 404)
    if not Classification.is_accessible(user['classification'], submission['classification']):
        return make_api_response(
            "", f"Your are not allowed get ontology files for the submission related to this alert: {alert_id}", 403)

    # Get all the results keys
    keys = [k for k in submission['results'] if not k.endswith(".e")]

    # Only use keys matching theses sha256s
    if sha256s:
        tmp_keys = []
        for sha256 in sha256s:
            tmp_keys.extend([k for k in keys if k.startswith(sha256)])
        keys = tmp_keys

    # Only use keys matching theses services
    if services:
        tmp_keys = []
        for service in services:
            tmp_keys.extend([k for k in keys if f".{service}." in k])
        keys = tmp_keys

    # Pull the results for the keys
    try:
        results = STORAGE.result.multiget(keys, as_dictionary=False, as_obj=False)
    except MultiKeyError as e:
        results = e.partial_output

    # Compile information to be added to the ontology
    updates = {
        'file': {
            'parent': alert['file']['sha256']
        },
        'submission': {
            'metadata': alert.get('metadata', {}),
            'date': alert['ts'],
            'source_system': config.ui.fqdn,
            'sid': submission['sid'],
            'classification': submission['classification'],
            'submitter': submission['params']['submitter'],
            'groups': submission['params']['groups'],
            'max_score': submission['max_score']
        }

    }

    # Set the list of file names
    fnames = {x['sha256']: [x['name']] for x in submission['files']}

    # Generate ontology files based of the results
    sio = generate_ontology_file(results, user, updates=updates, fnames=fnames)
    data = sio.getvalue()
    return make_file_response(data, f"alert_{alert_id}.ontology", len(data))


@ontology_api.route("/submission/<sid>/", methods=["GET"])
@api_login(require_role=[ROLES.submission_view])
def get_ontology_for_submission(sid, **kwargs):
    """
    WARNING:
        This APIs output is considered stable but the ontology model itself is still in its
        alpha state. Do not use the results of this API in a production system just yet.

    Get all ontology files for a given submission

    Variables:
    sid         => Submission ID to get ontology files for

    Arguments:
    sha256      => Only get ontology files for this file, multiple values allowed (optional)
    service     => Only get ontology files for this service, multiple values allowed (optional)

    Data Block:
    None

    Result example:      (File where each line is a result ontology record)
    {"header":{"md5":"5fa76...submitter":"admin"}}
    {"header":{"md5":"6c3af...submitter":"admin"}}
    {"header":{"md5":"c8e69...submitter":"admin"}}
    """
    user = kwargs['user']
    sha256s = request.args.getlist('sha256', None)
    services = request.args.getlist('service', None)

    # Get submission for sid
    submission = STORAGE.submission.get(sid, as_obj=False)
    if not submission:
        return make_api_response("", f"There is no submission with sid: {sid}", 404)
    if not Classification.is_accessible(user['classification'], submission['classification']):
        return make_api_response("", f"Your are not allowed get ontology files for this submission: {sid}", 403)

    # Get all the results keys
    keys = [k for k in submission['results'] if not k.endswith(".e")]

    # Only use keys matching theses sha256s
    if sha256s:
        tmp_keys = []
        for sha256 in sha256s:
            tmp_keys.extend([k for k in keys if k.startswith(sha256)])
        keys = tmp_keys

    # Only use keys matching theses services
    if services:
        tmp_keys = []
        for service in services:
            tmp_keys.extend([k for k in keys if f".{service}." in k])
        keys = tmp_keys

    # Pull the results for the keys
    try:
        results = STORAGE.result.multiget(keys, as_dictionary=False, as_obj=False)
    except MultiKeyError as e:
        results = e.partial_output

    # Compile information to be added to the ontology
    updates = {
        'file': {
            'parent': submission['files'][0]['sha256'],
        },
        'submission': {
            'metadata': submission.get('metadata', {}),
            'date': submission['times']['submitted'],
            'source_system': config.ui.fqdn,
            'sid': sid,
            'classification': submission['classification'],
            'submitter': submission['params']['submitter'],
            'groups': submission['params']['groups'],
            'max_score': submission['max_score']
        }

    }

    # Set the list of file names
    fnames = {x['sha256']: [x['name']] for x in submission['files']}

    # Generate ontology files based of the results
    sio = generate_ontology_file(results, user, updates=updates, fnames=fnames)
    data = sio.getvalue()
    return make_file_response(data, f"submission_{sid}.ontology", len(data))


@ontology_api.route("/file/<sha256>/", methods=["GET"])
@api_login(require_role=[ROLES.submission_view])
def get_ontology_for_file(sha256, **kwargs):
    """
    WARNING:
        This APIs output is considered stable but the ontology model itself is still in its
        alpha state. Do not use the results of this API in a production system just yet.

    Get all ontology files for a given file

    Variables:
    sha256      => Hash of the files to fetch ontology files for

    Arguments:
    service     => Only get ontology files for this service, multiple values allowed (optional)
    all         => If there multiple ontology results for the same file get them all

    Data Block:
    None

    Result example:      (File where each line is a result ontology record)
    {"header":{"md5":"5fa76...submitter":"admin"}}
    {"header":{"md5":"5fa76...submitter":"admin"}}
    {"header":{"md5":"5fa76...submitter":"admin"}}
    """
    user = kwargs['user']
    services = request.args.getlist('service', None)
    all = request.args.get('all', 'false').lower() in ['true', '']

    # Get file data for hash
    file_data = STORAGE.file.get(sha256, as_obj=False)
    if not file_data:
        return make_api_response("", f"There is no file with this hash: {sha256}", 404)
    if not Classification.is_accessible(user['classification'], file_data['classification']):
        return make_api_response("", f"Your are not allowed get ontology files for this hash: {sha256}", 403)

    # Generate the queries to get the results
    query = f"sha256:{sha256} AND response.supplementary.description:ontology"
    filters = []
    if services:
        filters.append(" OR ".join([f'response.service_name:{service}' for service in services]))

    # Get the result keys
    if all:
        keys = [
            x['id']
            for x in STORAGE.result.stream_search(
                query, fl="id", filters=filters, access_control=user["access_control"],
                as_obj=False, item_buffer_size=1000)]
    else:
        service_resp = STORAGE.result.grouped_search("response.service_name", query=query, fl='id', filters=filters,
                                                     group_sort="created desc", access_control=user["access_control"],
                                                     as_obj=False)

        keys = [k for service in service_resp['items'] for k in service['items'][0].values()]

    # Pull the results for the keys
    try:
        results = STORAGE.result.multiget(keys, as_dictionary=False, as_obj=False)
    except MultiKeyError as e:
        results = e.partial_output

    # Compile information to be added to the ontology
    updates = {
        'submission': {
            'date': file_data['seen']['last'],
            'source_system': config.ui.fqdn,
            'classification': file_data['classification']
        }
    }

    # Generate ontology files based of the results
    sio = generate_ontology_file(results, user, updates=updates)
    data = sio.getvalue()
    return make_file_response(data, f"file_{sha256}.ontology", len(data))
