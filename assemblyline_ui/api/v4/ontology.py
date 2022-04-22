import json

from flask import request
from io import BytesIO

from assemblyline.datastore.exceptions import MultiKeyError
from assemblyline_ui.api.base import api_login, make_api_response, make_file_response, make_subapi_blueprint
from assemblyline_ui.config import STORAGE, LOGGER, FILESTORE, CLASSIFICATION as Classification

SUB_API = 'ontology'
ontology_api = make_subapi_blueprint(SUB_API, api_version=4)
ontology_api._doc = "Download ontology results from the system"


def generate_ontology_file(results, user):
    # Load ontology files
    bio = BytesIO()
    for r in results:
        for supp in r.get('response', {}).get('supplementary', {}):
            if supp['name'].endswith('.ontology'):
                data = FILESTORE.get(supp['sha256'])
                try:
                    ontology = json.loads(data)
                    sha256 = ontology['header']['sha256']
                    c12n = ontology['header']['classification']
                    if sha256 == r['sha256'] and Classification.is_accessible(user['classification'], c12n):
                        bio.write(data + b'\n')
                except Exception as e:
                    LOGGER.warning(f"An error occured while fetching ontology files: {str(e)}")

    # Flush and reset buffer
    bio.flush()
    bio.seek(0)

    return bio


@ontology_api.route("/submission/<sid>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_ontology_for_submission(sid, **kwargs):
    """
    Get all ontology files for a given submission

    Variables:
    sid         => Submission ID to get ontology files for

    Arguments:
    sha256      => Only get ontology files for this file, multiple values allowed (optional)
    service     => Only get ontology files for this service, multiple values allowed (optional)

    Data Block:
    None

    Result example:
    <file where each line is an ontology result>
    """
    user = kwargs['user']
    submission = STORAGE.submission.get(sid, as_obj=False)
    sha256s = request.args.getlist('sha256', None)
    services = request.args.getlist('service', None)

    if not submission:
        return make_api_response("", f"There are not submission with sid: {sid}", 404)

    if Classification.is_accessible(user['classification'], submission['classification']):
        # Get all the results
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

        try:
            results = STORAGE.result.multiget(keys, as_dictionary=False, as_obj=False)
        except MultiKeyError as e:
            results = e.partial_output

        # Generate ontology files based of the results
        bio = generate_ontology_file(results, user)
        return make_file_response(bio.read(), f"submission_{sid}.ontology", bio.getbuffer().nbytes)
    else:
        return make_api_response("", f"Your are not allowed get ontology files for this submission: {sid}", 403)


@ontology_api.route("/file/<sha256>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_ontology_for_file(sha256, **kwargs):
    """
    Get all ontology files for a given file

    Variables:
    sha256      => Hash of the files to fetch ontology files for

    Arguments:
    service     => Only get ontology files for this service, multiple values allowed (optional)
    all         => If there multiple ontology results for the same file get them all

    Data Block:
    None

    Result example:
    <file where each line is an ontology result>
    """
    user = kwargs['user']
    file_data = STORAGE.file.get(sha256, as_obj=False)
    services = request.args.getlist('service', None)
    all = request.args.get('all', 'false').lower() in ['true', '']

    if not file_data:
        return make_api_response("", f"There are not file with this hash: {sha256}", 404)

    if Classification.is_accessible(user['classification'], file_data['classification']):
        # Get all the results
        query = f"id:{sha256}* AND response.supplementary.name:*.ontology"
        filters = []
        if services:
            filters.append(" OR ".join([f'response.service_name:{service}' for service in services]))

        if all:
            keys = [x['id'] for x in STORAGE.result.stream_search(query, fl="id", filters=filters,
                                                                  access_control=user["access_control"], as_obj=False)]
        else:
            service_resp = STORAGE.result.grouped_search("response.service_name", query=query, fl='id', filters=filters,
                                                         sort="created desc", access_control=user["access_control"],
                                                         as_obj=False)

            keys = [k for service in service_resp['items'] for k in service['items'][0].values()]

        try:
            results = STORAGE.result.multiget(keys, as_dictionary=False, as_obj=False)
        except MultiKeyError as e:
            results = e.partial_output

        # Generate ontology files based of the results
        bio = generate_ontology_file(results, user)
        return make_file_response(bio.read(), f"file_{sha256}.ontology", bio.getbuffer().nbytes)
    else:
        return make_api_response("", f"Your are not allowed get ontology files for this hash: {sha256}", 403)
