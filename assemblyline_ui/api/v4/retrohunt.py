import re
import typing

import hauntedhouse
from assemblyline.datastore.collection import Index
from assemblyline.datastore.exceptions import SearchException
from assemblyline.odm.models.retrohunt import Retrohunt
from assemblyline.odm.models.user import ROLES
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import CLASSIFICATION, STORAGE, config
from flask import request

SUB_API = 'retrohunt'
retrohunt_api = make_subapi_blueprint(SUB_API, api_version=4)
retrohunt_api._doc = "Run yara signatures over all files."


haunted_house_client = None
if config.retrohunt:
    haunted_house_client = hauntedhouse.Client(
        address=config.retrohunt.url,
        api_key=config.retrohunt.api_key,
        classification=CLASSIFICATION.original_definition,
        verify=config.retrohunt.tls_verify
    )


def is_finished(result):
    if hasattr(result, 'finished'):
        return result.finished
    elif hasattr(result, 'stage'):
        return result.stage.lower() == 'finished'
    return False


def get_hits(ids: list = [], user=None):
    fields = ["hits.query", "hits.offset", "hits.rows", "hits.sort", "hits.fl", "hits.filters", 'hits.track_total_hits']

    if request.method == "POST":
        req_data = request.json
    else:
        req_data = request.args

    params = {k.rpartition('hits.')[2]: req_data.get(k, None) for k in fields if req_data.get(k, None) is not None}

    params.setdefault('query', '*')
    params.setdefault('offset', '0')
    params.setdefault('rows', '20')
    params.setdefault('sort', 'seen.last desc')
    params.setdefault('key_space', ids)

    if (user is not None):
        params.update({'access_control': user['access_control']})

    # use_archive = req_data.get('hits.use_archive', False)
    # archive_only = req_data.get('hits.archive_only', False)
    # if archive_only:
    #     params['index_type'] = Index.ARCHIVE
    # elif use_archive:
    #     params['index_type'] = Index.HOT_AND_ARCHIVE
    # else:
    #     params['index_type'] = Index.HOT

    params['index_type'] = Index.HOT_AND_ARCHIVE
    params['as_obj'] = False

    try:
        return make_api_response(STORAGE.file.search(**params))
    except SearchException as e:
        return make_api_response("", f"SearchException: {e}", 400)


def get_errors(errors: list):

    if request.method == "POST":
        req_data = request.json
    else:
        req_data = request.args

    offset = int(req_data.get('errors.offset', 0))
    rows = int(req_data.get('errors.rows', 20))

    query = req_data.get('errors.query', ".*")
    try:
        p = re.compile(query)
        errors = [error for error in errors if p.match(error)]
    except re.error:
        errors = errors

    sort = req_data.get('errors.sort', None)
    if sort is not None:
        if 'asc' in sort.lower():
            errors.sort()
        elif 'desc' in sort.lower():
            errors.sort(reverse=True)

    if (errors is None):
        return {
            'offset': offset,
            'rows': rows,
            'total': None,
            'items': []
        }
    else:
        return {
            'offset': offset,
            'rows': rows,
            'total': len(errors),
            'items': errors[offset:offset + rows]
        }


def get_job_details(doc: dict, user):
    code = doc['code']

    # If the datastore document is finished, there no need to get the latest information.
    status = None
    if not doc.get('finished'):
        status = haunted_house_client.search_status_sync(code=code, access=user['classification'])

        # If the retrohunt job is finished, update the datastore to the latest values
        if is_finished(status):
            doc['errors'] = status.errors
            doc['finished'] = True
            doc['hits'] = status.hits
            doc['total_errors'] = len(status.errors)
            doc['total_hits'] = len(status.hits)
            doc['truncated'] = status.truncated
            STORAGE.retrohunt.save(code, doc)

        # If the retrohunt job is not finished, get the current state values
        else:
            value_fields = ['errors', 'finished', 'hits', 'phase', 'progress', 'truncated']
            doc.update({k: status.get(k, None) for k in value_fields if status.get(k, None) is not None})

            pourcentage = 100
            if status.get('phase', None) == 'filtering':
                progress = status.get('progress', (1, 1))
                pourcentage = 100 * progress[0] / progress[1]
            elif status.get('phase', None) == 'yara':
                progress = status.get('progress', (1, 1))
                pourcentage = 100 * (progress[0] - progress[1]) / progress[0]

            doc.update({
                'pourcentage': pourcentage,
                'total_errors': len(status.get('errors', doc['errors'])),
                'total_hits': len(status.get('hits', doc['hits'])),
            })

    return doc


@retrohunt_api.route("/", methods=["PUT"])
@api_login(require_role=[ROLES.retrohunt_run])
def create_retrohunt_job(**kwargs):
    """
    Create a new search over file storage.

    Arguments:
        yara_signature  => yara signature to search with
        archive_only    => Should the search only be run on archived files
        description     => Textual description of this search
        classification  => Classification level for the search

    Response Fields:    => It should always be the same as polling the details of the search
    """
    user = kwargs['user']

    # Make sure retrohunt is configured
    if haunted_house_client is None:
        return make_api_response({}, err="retrohunt not configured for this system", status_code=501)

    # Parse the input document
    try:
        signature = str(request.json['yara_signature'])
        description = str(request.json['description'])
        archive_only = bool(request.json['archive_only'])
        classification = str(request.json['classification'])
    except KeyError as err:
        return make_api_response({}, err=f"Missing required argument: {err}", status_code=400)

    # Make sure the user has high enough access
    classification = CLASSIFICATION.normalize_classification(classification)
    if not CLASSIFICATION.is_accessible(user['classification'], classification):
        return make_api_response({}, err="Searches may not be above user access.", status_code=403)

    # Parse the signature and send it to the retrohunt api
    status = haunted_house_client.start_search_sync(
        yara_rule=signature,
        access_control=classification,
        group=user['uname'],
        archive_only=archive_only
    )

    doc = Retrohunt({
        'archive_only': archive_only,
        'classification': classification,
        'code': status.code,
        'creator': user['uname'],
        'description': description,
        'errors': [],
        'finished': False,
        'hits': [],
        'raw_query': hauntedhouse.client.query_from_yara(signature),
        'tags': {},
        'yara_signature': signature,
    }).as_primitives()

    STORAGE.retrohunt.save(status.code, doc)

    return make_api_response(get_latest_job_details(status, doc, user))


@retrohunt_api.route("/<code>/", methods=["GET", "POST"])
@api_login(require_role=[ROLES.retrohunt_view])
def get_retrohunt_job_detail(code, **kwargs):
    """
    Get the details of a completed or an in progress retrohunt job.

    Variables:
        code                => Search code to be retrieved

    Response Fields:
    {
        "archive_only": False,                      #   Defines the indices used for this retrohunt job
        "classification": "TLP:WHITE",              #   Classification string for the retrohunt job and results list
        "code": "0x",                               #   Unique code identifying this retrohunt job
        "created": "2023-01-01T00:00:00.000000Z",   #   Timestamp when this retrohunt job started
        "creator": "admin",                         #   User who created this retrohunt job
        "description": "This is the description",   #   Human readable description of this retrohunt job
        "finished": True,                           #   Boolean indicating if this retrohunt job is finished
        "id": "0x",                                 #   Unique code identifying this retrohunt job
        "phase": "finished",                        #   Phase the job is on : 'filtering' | 'yara' | 'finished'
        "pourcentage": 0,                           #   Pourcentage of completion the phase is at
        "progress": [1, 1],                         #   Progress values when the job is running
        "raw_query": "(min 1 of (100))",            #   Text of filter query derived from yara signature
        "tags": {},                                 #   Tags describing this retrohunt job
        "total_hits": 100,                          #   Total number of hits when the job first ran
        "total_errors": 80,                         #   Total number of errors encountered during the job
        "truncated": False,                         #   Indicates if the list of hits been truncated at some limit
        "yara_signature":                           #   Text of original yara signature run
                            rule my_rule {
                                meta:
                                    KEY = "VALUE"
                                strings:
                                    $name = "string"
                                condition:
                                    any of them
                            }
    }
    """
    user = kwargs['user']

    # Make sure retrohunt is configured
    if haunted_house_client is None:
        return make_api_response({}, err="retrohunt not configured for this system", status_code=501)

    # Fetch the data from elasticsearch, use that as access filter
    doc: dict = STORAGE.retrohunt.get(code, as_obj=False)
    if doc is None:
        return make_api_response({}, err="Not Found.", status_code=404)
    if not CLASSIFICATION.is_accessible(user['classification'], doc['classification']):
        return make_api_response({}, err="Access denied.", status_code=403)

    # Get status information from retrohunt server
    status = None
    if not doc.get('finished'):
        user = kwargs['user']
        status = haunted_house_client.search_status_sync(code=code, access=user['classification'])

        if is_finished(status):
            doc['errors'] = status.errors
            doc['finished'] = True
            doc['hits'] = status.hits
            doc['total_errors'] = len(status.errors)
            doc['total_hits'] = len(status.hits)
            doc['truncated'] = status.truncated
            STORAGE.retrohunt.save(code, doc)

    if status is not None:
        phase = status.phase
        progress = status.progress
        total_errors = len(status.errors)
        total_hits = len(status.hits)
        truncated = status.truncated
    else:
        phase = 'finished'
        progress = (1, 1)
        total_errors = len(doc['errors'])
        total_hits = doc['total_hits']
        truncated = doc['truncated']

    pourcentage = 100
    if phase == 'filtering':
        pourcentage = 100 * progress[0] / progress[1]
    elif phase == 'yara':
        pourcentage = 100 * (progress[0] - progress[1]) / progress[0]

    doc.pop('hits')
    doc.pop('errors')

    doc.update({
        'finished': True if status is None else is_finished(status),
        'phase': phase,
        'pourcentage': pourcentage,
        'progress': progress,
        'total_errors': total_errors,
        'total_hits': total_hits,
        'truncated': truncated,
    })

    return make_api_response(doc)


@retrohunt_api.route("/hits/<code>/", methods=["GET"])
@api_login(require_role=[ROLES.retrohunt_view])
def get_retrohunt_job_hits(code, **kwargs):
    """
    Get hit results of a retrohunt job completed or in progress.

    Variables:
        code                    =>  Search code to be retrieved

    Optional Arguments:
        query                   =>  Query to filter the file list
        offset                  =>  Offset at which we start giving files
        rows                    =>  Numbers of files to return
        filters                 =>  List of additional filter queries limit the data
        sort                    =>  How to sort the results (not available in deep paging)
        fl                      =>  List of fields to return

    Response Fields:
    {
        "total": 200,           #   Total results found
        "offset": 0,            #   Offset in the result list
        "rows": 100,            #   Number of results returned
        "items": [              #   List of files
            {
                "classification": "TLP:CLEAR",
                "entropy": 0.00,
                "from_archive": False,
                "id": "0aa",
                "is_section_image": False,
                "label_categories": {
                    "attribution": [],
                    "info": [],
                    "technique": []
                },
                "labels": [],
                "md5": "0aa",
                "seen": {
                    "count": 1,
                    "first": "2023-01-01T00:00:00.000000Z",
                    "last": "2023-01-01T00:00:00.000000Z"
                },
                "sha1": "0aa",
                "sha256": "0aa",
                "size": 100,
                "tlsh": "T134",
                "type": "text/json"
            },
            {
                ...
            }
        ]
    }
    """
    user = kwargs['user']

    # Make sure retrohunt is configured
    if haunted_house_client is None:
        return make_api_response({}, err="retrohunt not configured for this system", status_code=501)

    # Fetch the retrohunt job from elasticsearch
    doc = STORAGE.retrohunt.get(code, as_obj=False)

    # Make sure the user has the right classification to access this retrohunt job
    if doc is None:
        return make_api_response({}, err="Not Found.", status_code=404)
    if not CLASSIFICATION.is_accessible(user['classification'], doc['classification']):
        return make_api_response({}, err="Access denied.", status_code=403)

    # Get status information from retrohunt server
    status = None
    if not doc.get('finished'):
        user = kwargs['user']
        status = haunted_house_client.search_status_sync(code=code, access=user['classification'])

        if is_finished(status):
            doc['hits'] = status.hits
            STORAGE.retrohunt.save(code, doc)

    # Get the request parameters and apply the multi_field parameter to it
    multi_fields = ['filters']
    if request.method == "POST":
        req_data = request.json
        params = {k: req_data.get(k, None) for k in multi_fields if req_data.get(k, None) is not None}
    else:
        req_data = request.args
        params = {k: req_data.getlist(k, None) for k in multi_fields if req_data.get(k, None) is not None}

    # Set the default search parameters
    params.setdefault('query', '*')
    params.setdefault('offset', '0')
    params.setdefault('rows', '10')
    params.setdefault('sort', 'seen.last desc')
    params.setdefault('access_control', user['access_control'])
    params.setdefault('as_obj', False)
    params.setdefault('key_space', doc['hits'])
    params.setdefault('index_type', Index.HOT_AND_ARCHIVE)
    params.setdefault('track_total_hits', True)

    # Append the other request parameters
    fields = ["query", "offset", "rows", "sort", "fl", 'track_total_hits']
    params.update({k: req_data.get(k, None) for k in fields if req_data.get(k, None) is not None})

    try:
        return make_api_response(STORAGE.file.search(**params))
    except SearchException as e:
        return make_api_response("", f"SearchException: {e}", 400)


@retrohunt_api.route("/errors/<code>/", methods=["GET"])
@api_login(require_role=[ROLES.retrohunt_view])
def get_retrohunt_job_errors(code, **kwargs):
    """
    Get errors of a retrohunt job completed or in progress.

    Variables:
        code                    =>  Search code to be retrieved

    Optional Arguments:
        offset                  =>  Offset at which we start giving files
        rows                    =>  Numbers of files to return
        sort                    =>  How to sort the errors

    Response Fields:
    {
        "total": 200,           #   Total errors found
        "offset": 0,            #   Offset in the error list
        "rows": 100,            #   Number of errors returned
        "items": [              #   List of errors
            "File not available: channel closed",
            ...
        ]
    }
    """
    user = kwargs['user']

    # Make sure retrohunt is configured
    if haunted_house_client is None:
        return make_api_response({}, err="retrohunt not configured for this system", status_code=501)

    # Fetch the retrohunt job from elasticsearch
    doc = STORAGE.retrohunt.get(code, as_obj=False)

    # Make sure the user has the right classification to access this retrohunt job
    if doc is None:
        return make_api_response({}, err="Not Found.", status_code=404)
    if not CLASSIFICATION.is_accessible(user['classification'], doc['classification']):
        return make_api_response({}, err="Access denied.", status_code=403)

    # Get status information from retrohunt server
    status = None
    if not doc.get('finished'):
        user = kwargs['user']
        status = haunted_house_client.search_status_sync(code=code, access=user['classification'])

        if is_finished(status):
            doc['errors'] = status.errors
            STORAGE.retrohunt.save(code, doc)

    if request.method == "POST":
        req_data = request.json
    else:
        req_data = request.args

    errors = doc['errors']
    offset = int(req_data.get('offset', 0))
    rows = int(req_data.get('rows', 20))

    if errors is None:
        return {
            'offset': offset,
            'rows': rows,
            'total': None,
            'items': []
        }

    sort = req_data.get('sort', None)
    if sort is not None:
        if 'asc' in sort.lower():
            errors.sort()
        elif 'desc' in sort.lower():
            errors.sort(reverse=True)

    return make_api_response({
        'offset': offset,
        'rows': rows,
        'total': len(errors),
        'items': errors[offset:offset + rows]
    })


@retrohunt_api.route("/types/<code>/", methods=["GET"])
@api_login(require_role=[ROLES.retrohunt_view])
def get_retrohunt_job_types(code, **kwargs):
    """
    Get types distribution of a retrohunt job completed or in progress.

    Variables:
        code                    =>  Search code to be retrieved

    Optional Arguments:
        query                   =>  Query to filter the file list
        filters                 =>  List of additional filter queries limit the data

    Result example:
    {                 # Facetting results
        "value_0": 2,
        ...
        "value_N": 19,
    }
    """
    user = kwargs['user']

    # Make sure retrohunt is configured
    if haunted_house_client is None:
        return make_api_response({}, err="retrohunt not configured for this system", status_code=501)

    # Fetch the retrohunt job from elasticsearch
    doc = STORAGE.retrohunt.get(code, as_obj=False)

    # Make sure the user has the right classification to access this retrohunt job
    if doc is None:
        return make_api_response({}, err="Not Found.", status_code=404)
    if not CLASSIFICATION.is_accessible(user['classification'], doc['classification']):
        return make_api_response({}, err="Access denied.", status_code=403)

    # Get status information from retrohunt server
    status = None
    if not doc.get('finished'):
        user = kwargs['user']
        status = haunted_house_client.search_status_sync(code=code, access=user['classification'])

        if is_finished(status):
            doc['hits'] = status.hits
            STORAGE.retrohunt.save(code, doc)

    # Get the request parameters and apply the multi_field parameter to it
    multi_fields = ['filters']
    if request.method == "POST":
        req_data = request.json
        params = {k: req_data.get(k, None) for k in multi_fields if req_data.get(k, None) is not None}
    else:
        req_data = request.args
        params = {k: req_data.getlist(k, None) for k in multi_fields if req_data.get(k, None) is not None}

    # Set the default search parameters
    params.setdefault('query', '*')
    params.setdefault('access_control', user['access_control'])
    params.setdefault('key_space', doc['hits'])
    params.setdefault('index_type', Index.HOT_AND_ARCHIVE)

    # Append the other request parameters
    fields = ["query"]
    params.update({k: req_data.get(k, None) for k in fields if req_data.get(k, None) is not None})

    try:
        return make_api_response(STORAGE.file.facet('type', **params))
    except SearchException as e:
        return make_api_response("", f"SearchException: {e}", 400)
