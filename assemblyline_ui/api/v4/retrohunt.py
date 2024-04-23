import typing

from assemblyline.common.isotime import now_as_iso
from assemblyline.common.forge import get_hauntedhouse_client
# from assemblyline.common.threading import APMAwareThreadPoolExecutor
from assemblyline.datastore.collection import Index
from assemblyline.datastore.exceptions import SearchException
from assemblyline.odm.models.user import ROLES
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import CLASSIFICATION, STORAGE, config, LOGGER
from flask import request, Response

SUB_API = 'retrohunt'
retrohunt_api = make_subapi_blueprint(SUB_API, api_version=4)
retrohunt_api._doc = "Run yara signatures over all files."

SECONDS_PER_DAY = 24 * 60 * 60

haunted_house_client = get_hauntedhouse_client(config)


@retrohunt_api.route("/", methods=["PUT"])
@api_login(require_role=[ROLES.retrohunt_run])
def create_retrohunt_job(**kwargs):
    """
    Create a new search over file storage.

    Arguments:
        indices               => One of 'hot', 'archive', or 'hot_and_archive'
        classification        => Classification level for the search/rule
        search_classification => Classification visibility search is run with
        description           => Textual description of this search
        yara_signature        => YARA signature to search with
        ttl                   => Time to live for this retrohunt job

    Response Fields:    => Body of retrohunt object
    """
    user = kwargs['user']
    body = request.get_json()
    if not body:
        return make_api_response({}, err="Malformed request body", status_code=400)

    # Make sure retrohunt is configured
    if haunted_house_client is None:
        return make_api_response({}, err="retrohunt not configured for this system", status_code=501)

    # Parse the input document
    try:
        signature = str(body['yara_signature'])
        description = str(body['description'])
        indices = str(body['indices'])
        classification = str(body['classification'])
        search_classification = str(body['search_classification'])
    except KeyError as err:
        return make_api_response({}, err=f"Missing required argument: {err}", status_code=400)

    # Make sure the user has high enough access
    classification = CLASSIFICATION.normalize_classification(classification)
    if not CLASSIFICATION.is_accessible(user['classification'], classification):
        return make_api_response({}, err="Searches may not be above user access.", status_code=403)
    search_classification = CLASSIFICATION.normalize_classification(search_classification)
    if not CLASSIFICATION.is_accessible(user['classification'], search_classification):
        return make_api_response({}, err="Searches may not be above user access.", status_code=403)

    # Enforce maximum DTL
    max_expiry = None
    if config.retrohunt.dtl:
        max_expiry = int(body['ttl']) if body['ttl'] else config.retrohunt.dtl
        if max_expiry and config.retrohunt.max_dtl > 0:
            max_expiry = min(max_expiry, config.retrohunt.max_dtl)
        max_expiry = now_as_iso(max_expiry * SECONDS_PER_DAY)

    try:
        # Parse the signature and send it to the retrohunt api
        key = haunted_house_client.start_search(
            yara_rule=signature,
            rule_classification=classification,
            search_classification=search_classification,
            indices=indices,
            creator=user['uname'],
            description=description,
            expiry=max_expiry,
        )

        # Fetch the details after the retrohunt server has parsed them and saved them to elasticsearch
        doc = STORAGE.retrohunt.get(key, as_obj=False)

        return make_api_response(doc)
    except Exception as e:
        return make_api_response("", f"{e}", 400)


@retrohunt_api.route("/repeat/", methods=["POST"])
@api_login(require_role=[ROLES.retrohunt_run])
def repeat_retrohunt_job(**kwargs):
    """
    Repeat a search over file storage.

    Arguments:
        key                    => Key of the job to repeat
        search_classification  => Classification visibility search is run with
        ttl                    => Optional, new expiry date for the search
    """
    user = kwargs['user']
    body = request.get_json()
    if not body:
        return make_api_response({}, err="Malformed request body", status_code=400)

    # Make sure retrohunt is configured
    if haunted_house_client is None:
        return make_api_response({}, err="retrohunt not configured for this system", status_code=501)

    # Parse the input document
    try:
        key = str(body['key'])
        search_classification = str(body['search_classification'])
    except KeyError as err:
        return make_api_response({}, err=f"Missing required argument: {err}", status_code=400)

    # Load existing search
    doc = STORAGE.retrohunt.get(key, as_obj=False)
    if doc is None:
        return make_api_response({}, err="retrohunt job indicated does not exist", status_code=404)

    # Make sure the user has high enough access
    if not CLASSIFICATION.is_accessible(user['classification'], doc['classification']):
        return make_api_response({}, err="retrohunt job indicated does not exist", status_code=404)

    search_classification = CLASSIFICATION.normalize_classification(search_classification)
    if not CLASSIFICATION.is_accessible(user['classification'], search_classification):
        return make_api_response({}, err="Searches may not be above user access.", status_code=403)

    # Enforce maximum DTL
    max_expiry = None
    if config.retrohunt.dtl:
        max_expiry = int(body['ttl']) if body['ttl'] else config.retrohunt.dtl
        if max_expiry and config.retrohunt.max_dtl > 0:
            max_expiry = min(max_expiry, config.retrohunt.max_dtl)
        max_expiry = now_as_iso(max_expiry * SECONDS_PER_DAY)

    try:
        # Parse the signature and send it to the retrohunt api
        haunted_house_client.repeat_search(
            key=key,
            search_classification=search_classification,
            expiry=max_expiry,
        )

        # Fetch the details after the retrohunt server has parsed them and saved them to elasticsearch
        doc = STORAGE.retrohunt.get(key, as_obj=False)

        return make_api_response(doc)
    except Exception as e:
        return make_api_response("", f"{e}", 400)


@retrohunt_api.route("/", methods=["GET", "POST"])
@api_login(require_role=["retrohunt_view"])
def search_retrohunt_jobs(**kwargs) -> Response:
    """
    Search through the retrohunt index for a given query.
    Uses lucene search syntax for query.

    Optional Arguments:
        query                   =>  Query to search for
        offset                  =>  Offset in the results
        rows                    =>  Number of results per page
        sort                    =>  How to sort the results (not available in deep paging)
        fl                      =>  List of fields to return
        filters                 =>  List of additional filter queries limit the data

    Data Block (POST ONLY):
    {
        "query": "*",           =>  Query to search for
        "offset": 0,            =>  Offset in the results
        "rows": 100,            =>  Max number of results
        "sort": "field asc",    =>  How to sort the results
        "fl": "id,score",       =>  List of fields to return
        "filters": ['fq']       =>  List of additional filter queries limit the data
    }

    Result example:
    {
        "total": 201,           =>  Total retrohunt jobs found
        "offset": 0,            =>  Offset in the retrohunt job list
        "rows": 20,             =>  Number of retrohunt jobs returned
        "items": []             =>  List of retrohunt jobs
    }
    """
    user = kwargs['user']

    # Make sure retrohunt is configured
    if haunted_house_client is None:
        return make_api_response({}, err="retrohunt not configured for this system", status_code=501)

    # Get the request parameters and apply the multi_field parameter to it
    multi_fields = ['filters']
    params: dict[str, typing.Any]
    if request.method == "POST":
        req_data = request.json
        params = {k: req_data.get(k, None) for k in multi_fields if req_data.get(k, None) is not None}
    else:
        req_data = request.args
        params = {k: req_data.getlist(k, None) for k in multi_fields if req_data.get(k, None) is not None}

    # Set the default search parameters
    params.setdefault('query', '*')
    params.setdefault('offset', '0')
    params.setdefault('rows', '20')
    params.setdefault('sort', 'created_time desc')
    params.setdefault('access_control', user['access_control'])
    params.setdefault('as_obj', False)
    params.setdefault('index_type', Index.HOT_AND_ARCHIVE)
    params.setdefault('track_total_hits', True)

    # Append the other request parameters
    fields = ["query", "offset", "rows", "sort", "fl", 'track_total_hits']
    params.update({k: req_data.get(k, None) for k in fields if req_data.get(k, None) is not None})

    fl = params.get('fl', '')
    if fl:
        params['fl'] = fl + ',key'
    else:
        params['fl'] = 'key'

    try:
        result = STORAGE.retrohunt.search(**params)
        items = result.get('items')
        LOGGER.warning("%s", items)

        if items:
            query = 'search: (' + ' OR '.join(item['key'] for item in items) + ')'
            counts = STORAGE.retrohunt_hit.facet("search", query=query,
                                                 access_control=user['access_control'], size=len(items))
            for item in items:
                item['total_hits'] = counts.get(item['key'], 0)

        return make_api_response(result)
    except SearchException as e:
        return make_api_response("", f"SearchException: {e}", 400)


@retrohunt_api.route("/<id>/", methods=["GET", "POST"])
@api_login(require_role=[ROLES.retrohunt_view])
def get_retrohunt_job_detail(id, **kwargs):
    """
    Get the details of a completed or an in progress retrohunt job.

    Variables:
        id                => ID of the retrohunt job to be retrieved

    Response Fields:
    {
        "classification": "TLP:WHITE",              #   Classification string for the retrohunt job and results list
        "code": "0x",                               #   Unique code identifying this retrohunt job
        "created": "2023-01-01T00:00:00.000000Z",   #   Timestamp when this retrohunt job started
        "creator": "admin",                         #   User who created this retrohunt job
        "description": "This is the description",   #   Human readable description of this retrohunt job
        "finished": True,                           #   Boolean indicating if this retrohunt job is finished
        "id": "0x",                                 #   Unique code identifying this retrohunt job
        "raw_query": "(min 1 of (100))",            #   Text of filter query derived from yara signature
        "tags": {},                                 #   Tags describing this retrohunt job
        "total_hits": 100,                          #   Total number of hits when the job first ran
        "total_errors": 80,                         #   Total number of errors encountered during the job
        "total_warnings": 80,                       #   Total number of warnings encountered during the job
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

    doc = STORAGE.retrohunt.get(id, as_obj=False)
    if not doc:
        return make_api_response({}, "This retrohunt job does not exist...", 404)

    if not user or not CLASSIFICATION.is_accessible(user['classification'], doc['classification']):
        return make_api_response({}, err="Access denied.", status_code=403)

    doc['total_errors'] = len(doc['errors'])
    doc['total_warnings'] = len(doc['warnings'])
    doc.pop('warnings', None)
    doc.pop('errors', None)
    return make_api_response(doc)


@retrohunt_api.route("/hits/<id>/", methods=["GET", "POST"])
@api_login(require_role=[ROLES.retrohunt_view])
def get_retrohunt_job_hits(id, **kwargs):
    """
    Get hit results of a retrohunt job completed or in progress.

    Variables:
        id                    =>  ID of the retrohunt job to be retrieved

    Optional Arguments:
        query                   =>  Query to filter the file list
        offset                  =>  Offset at which we start giving files
        rows                    =>  Number of files to return
        filters                 =>  List of additional filter queries limit the data
        sort                    =>  How to sort the results (not available in deep paging)
        fl                      =>  List of fields to return

    Data Block (POST ONLY):
    {
        "query": "id:*",        =>  Query to filter the file list
        "offset": "0",          =>  Offset at which we start giving files
        "rows": "0",            =>  Number of files to return
        "filters": "0",         =>  List of additional filter queries limit the data
        "sort": "0",            =>  How to sort the results (not available in deep paging)
        "fl": "0",              =>  List of fields to return
        "filters": ['fq']
    }

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

    doc = STORAGE.retrohunt.get(id, as_obj=False)
    if not doc:
        return make_api_response({}, "This retrohunt job does not exist...", 404)

    if not user or not CLASSIFICATION.is_accessible(user['classification'], doc['classification']):
        return make_api_response({}, err="Access denied.", status_code=403)

    try:
        params = {
            'query': f"search:{id}",
            'offset': 0,
            'rows': 10000,
            'fl': 'sha256',
            'as_obj': False,
            'index_type': Index.HOT_AND_ARCHIVE,
            'track_total_hits': True
        }

        hits = STORAGE.retrohunt_hit.search(**params)
        key_space = [item['sha256'] for item in hits['items']]

        params = {
            'query': '*',
            'offset': 0,
            'rows': 10,
            'sort': 'seen.last desc',
            'access_control': user['access_control'],
            'as_obj': False,
            'index_type': Index.HOT_AND_ARCHIVE,
            'track_total_hits': True,
            'key_space': key_space
        }

        multi_fields = ['filters']
        if request.method == "POST":
            req_data = request.json
            params.update({k: req_data.get(k, None) for k in multi_fields if req_data.get(k, None) is not None})
        else:
            req_data = request.args
            params.update({k: req_data.getlist(k, None) for k in multi_fields if req_data.get(k, None) is not None})

        fields = ["query", "offset", "rows", "sort", "fl", 'track_total_hits']
        params.update({k: req_data.get(k, None) for k in fields if req_data.get(k, None) is not None})

        return make_api_response(STORAGE.file.search(**params))
    except SearchException as e:
        return make_api_response("", f"SearchException: {e}", 400)


@retrohunt_api.route("/errors/<code>/", methods=["GET", "POST"])
@api_login(require_role=[ROLES.retrohunt_view])
def get_retrohunt_job_errors(code, **kwargs):
    """
    Get warnings and errors of a retrohunt job completed or in progress.

    Variables:
        code                    =>  Search code of the retrohunt job to be retrieved

    Optional Arguments:
        offset                  =>  Offset at which we start giving error messages
        rows                    =>  Number of error messages to return
        sort                    =>  How to sort the error messages

    Data Block (POST ONLY):
    {
        "offset": "0",          =>  Offset at which we start giving error messages
        "rows": "25",           =>  Number of error messages to return
        "sort": "asc",          =>  How to sort the error messages
    }

    Response Fields:
    {
        "total": 200,           #   Total warnings and errors found
        "offset": 0,            #   Offset in the error list
        "rows": 100,            #   Number of warnings and errors returned
        "items": [              #   List of warnings and errors
            "File not available: channel closed",
            ...
        ]
    }
    """
    user = kwargs['user']

    # Make sure retrohunt is configured
    if haunted_house_client is None:
        return make_api_response({}, err="retrohunt not configured for this system", status_code=501)

    # Get the latest retrohunt job information from both Elasticsearch and HauntedHouse
    doc = STORAGE.retrohunt.get(code, as_obj=False)

    # Make sure the user has the right classification to access this retrohunt job
    if doc is None:
        return make_api_response({}, err="Not Found.", status_code=404)

    if not user or not CLASSIFICATION.is_accessible(user['classification'], doc['classification']):
        return make_api_response({}, err="Access denied.", status_code=403)

    if request.method == "POST":
        req_data = request.json
    else:
        req_data = request.args

    errors = [{'type': 'error', 'message': item} for item in doc['errors']] + \
             [{'type': 'warning', 'message': item} for item in doc['warnings']]

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
        field = None
        if 'type' in sort:
            field = 'type'
        elif 'message' in sort:
            field = 'message'

        if field is not None:
            if 'asc' in sort.lower():
                errors = sorted(errors, key=lambda e: e[field])
            elif 'desc' in sort.lower():
                errors = sorted(errors, key=lambda e: e[field], reverse=True)

    return make_api_response({
        'offset': offset,
        'rows': rows,
        'total': len(errors),
        'items': errors[offset:offset + rows]
    })


@retrohunt_api.route("/types/<id>/", methods=["GET", "POST"])
@api_login(require_role=[ROLES.retrohunt_view])
def get_retrohunt_job_types(id, **kwargs):
    """
    Get types distribution of a retrohunt job completed or in progress.

    Variables:
        code                    =>  Search code of the retrohunt job to be retrieved

    Optional Arguments:
        query                   =>  Query to filter the file list
        mincount                =>  Minimum number of types for the fieldvalue to be returned
        filters                 =>  List of additional filter queries limit the data

    Data Block (POST ONLY):
    {
        "query": "id:*",        =>  Query to filter the file list
        "mincount": "0",        =>  Minimum number of types for the fieldvalue to be returned
        "filters": "0",         =>  List of additional filter queries limit the data
    }

    Result example:
    {                           # Facet results
        "value_0": 2,
        ...
        "value_N": 19,
    }
    """
    user = kwargs['user']

    # Make sure retrohunt is configured
    if haunted_house_client is None:
        return make_api_response({}, err="retrohunt not configured for this system", status_code=501)

    doc = STORAGE.retrohunt.get(id, as_obj=False)
    if doc is None:
        return make_api_response({}, err="Not Found.", status_code=404)

    if not user or not CLASSIFICATION.is_accessible(user['classification'], doc['classification']):
        return make_api_response({}, err="Access denied.", status_code=403)

    try:
        params = {
            'query': f"search:{id}",
            'offset': 0,
            'rows': 10000,
            'fl': 'sha256',
            'as_obj': False,
            'index_type': Index.HOT_AND_ARCHIVE,
            'track_total_hits': True
        }

        hits = STORAGE.retrohunt_hit.search(**params)
        key_space = [item['sha256'] for item in hits['items']]

        params = {
            'query': '*',
            'access_control': user['access_control'],
            'index_type': Index.HOT_AND_ARCHIVE,
            'key_space': key_space,
            'mincount': 1
        }

        multi_fields = ['filters']
        if request.method == "POST":
            req_data = request.json
            params.update({k: req_data.get(k, None) for k in multi_fields if req_data.get(k, None) is not None})
        else:
            req_data = request.args
            params.update({k: req_data.getlist(k, None) for k in multi_fields if req_data.get(k, None) is not None})

        fields = ["query", "mincount"]
        params.update({k: req_data.get(k, None) for k in fields if req_data.get(k, None) is not None})

        return make_api_response(STORAGE.file.facet('type', **params))
    except SearchException as e:
        return make_api_response("", f"SearchException: {e}", 400)
