
from flask import request

from assemblyline_ui.helper.search import BUCKET_MAP, list_all_fields, BUCKET_ORDER_MAP
from assemblyline.datastore import SearchException
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import STORAGE

SUB_API = 'search'
search_api = make_subapi_blueprint(SUB_API, api_version=4)
search_api._doc = "Perform search queries"


@search_api.route("/<bucket>/", methods=["GET", "POST"])
@api_login(required_priv=['R'])
def search(bucket, **kwargs):
    """
    Search through specified buckets for a given query.
    Uses lucene search syntax for query.

    Variables:
    bucket  =>   Bucket to search in (alert, submission,...)

    Arguments:
    query   =>   Query to search for

    Optional Arguments:
    deep_paging_id =>   ID of the next page or * to start deep paging
    filters        =>   List of additional filter queries limit the data
    offset         =>   Offset in the results
    rows           =>   Number of results per page
    sort           =>   How to sort the results (not available in deep paging)
    fl             =>   List of fields to return
    timeout        =>   Maximum execution time (ms)
    use_archive    =>   Allow access to the datastore achive (Default: True)

    Data Block (POST ONLY):
    {"query": "query",     # Query to search for
     "offset": 0,          # Offset in the results
     "rows": 100,          # Max number of results
     "sort": "field asc",  # How to sort the results
     "fl": "id,score",     # List of fields to return
     "timeout": 1000,      # Maximum execution time (ms)
     "filters": ['fq']}    # List of additional filter queries limit the data


    Result example:
    {"total": 201,                          # Total results found
     "offset": 0,                           # Offset in the result list
     "rows": 100,                           # Number of results returned
     "next_deep_paging_id": "asX3f...342",  # ID to pass back for the next page during deep paging
     "items": []}                           # List of results
    """
    if bucket not in BUCKET_MAP:
        return make_api_response("", f"Not a valid bucket to search in: {bucket}", 400)

    user = kwargs['user']
    fields = ["offset", "rows", "sort", "fl", "timeout", "deep_paging_id", "use_archive"]
    multi_fields = ['filters']

    if request.method == "POST":
        req_data = request.json
        params = {k: req_data.get(k, None) for k in fields if req_data.get(k, None) is not None}
        params.update({k: req_data.get(k, None) for k in multi_fields if req_data.get(k, None) is not None})
        query = req_data.get('query', None)

    else:
        req_data = request.args
        params = {k: req_data.get(k, None) for k in fields if req_data.get(k, None) is not None}
        params.update({k: req_data.getlist(k, None) for k in multi_fields if req_data.get(k, None) is not None})
        query = request.args.get('query', None)

    params.update({'access_control': user['access_control'], 'as_obj': False})
    params.setdefault('sort', BUCKET_ORDER_MAP[bucket])

    if not query:
        return make_api_response("", "There was no search query.", 400)

    try:
        return make_api_response(BUCKET_MAP[bucket].search(query, **params))
    except SearchException as e:
        return make_api_response("", f"SearchException: {e}", 400)


@search_api.route("/grouped/<bucket>/<group_field>/", methods=["GET", "POST"])
@api_login(required_priv=['R'])
def group_search(bucket, group_field, **kwargs):
    """
    Search through all relevant buckets for a given query and
    groups the data based on a specific field.
    Uses lucene search syntax for query.

    Variables:
    bucket       =>   Bucket to search in (alert, submission,...)
    group_field  =>   Field to group on

    Optional Arguments:
    group_sort   =>   How to sort the results inside the group
    limit        =>   Maximum number of results return for each groups
    query        =>   Query to search for
    filters      =>   List of additional filter queries limit the data
    offset       =>   Offset in the results
    rows         =>   Max number of results
    sort         =>   How to sort the results
    fl           =>   List of fields to return

    Data Block (POST ONLY):
    {"group_sort": "score desc",
     "limit": "10",
     "query": "query",
     "offset": 0,
     "rows": 100,
     "sort": "field asc",
     "fl": "id,score",
     "filters": ['fq']}


    Result example:
    {"total": 201,       # Total results found
     "offset": 0,        # Offset in the result list
     "rows": 100,        # Number of results returned
     "items": []}        # List of results
    """
    if bucket not in BUCKET_MAP:
        return make_api_response("", f"Not a valid bucket to search in: {bucket}", 400)

    user = kwargs['user']
    fields = ["group_sort", "limit", "query", "offset", "rows", "sort", "fl", "timeout"]
    multi_fields = ['filters']

    if request.method == "POST":
        req_data = request.json
        params = {k: req_data.get(k, None) for k in fields if req_data.get(k, None) is not None}
        params.update({k: req_data.get(k, None) for k in multi_fields if req_data.get(k, None) is not None})

    else:
        req_data = request.args
        params = {k: req_data.get(k, None) for k in fields if req_data.get(k, None) is not None}
        params.update({k: req_data.getlist(k, None) for k in multi_fields if req_data.get(k, None) is not None})

    params.update({'access_control': user['access_control'], 'as_obj': False})
    params.setdefault('sort', BUCKET_ORDER_MAP[bucket])

    if not group_field:
        return make_api_response("", "The field to group on was not specified.", 400)

    try:
        return make_api_response(BUCKET_MAP[bucket].grouped_search(group_field, **params))
    except SearchException as e:
        return make_api_response("", f"SearchException: {e}", 400)


# noinspection PyUnusedLocal
@search_api.route("/fields/<bucket>/", methods=["GET"])
@api_login(required_priv=['R'])
def list_bucket_fields(bucket, **kwargs):
    """
    List all available fields for a given bucket

    Variables:
    bucket  =>     Which specific bucket you want to know the fields for


    Arguments:
    None

    Data Block:
    None

    Result example:
    {
        "<<FIELD_NAME>>": {      # For a given field
            indexed: True,        # Is the field indexed
            stored: False,        # Is the field stored
            type: string          # What type of data in the field
            },
        ...

    }
    """
    if bucket in BUCKET_MAP or ():
        return make_api_response(BUCKET_MAP[bucket].fields())
    elif 'admin' in kwargs['user']['type'] and hasattr(STORAGE, bucket):
        return make_api_response(getattr(STORAGE, bucket).fields())
    elif bucket == "ALL":
        return make_api_response(list_all_fields())
    else:
        return make_api_response("", f"Not a valid bucket to search in: {bucket}", 400)


@search_api.route("/facet/<bucket>/<field>/", methods=["GET", "POST"])
@api_login(required_priv=['R'])
def facet(bucket, field, **kwargs):
    """
    Perform field analysis on the selected field. (Also known as facetting in lucene)
    This essentially counts the number of instances a field is seen with each specific values
    where the documents matches the specified queries.
    
    Variables:
    bucket       =>   Bucket to search in (alert, submission,...)
    field        =>   Field to analyse
    
    Optional Arguments:
    query        =>   Query to search for
    mincount    =>   Minimum item count for the fieldvalue to be returned
    filters      =>   Additional query to limit to output

    Data Block (POST ONLY):
    {"query": "id:*",
     "mincount": "10",
     "filters": ['fq']}
    
    Result example:
    {                 # Facetting results
     "value_0": 2,
     ...
     "value_N": 19,
    }
    """
    if bucket not in BUCKET_MAP:
        return make_api_response("", f"Not a valid bucket to search in: {bucket}", 400)
    collection = BUCKET_MAP[bucket]

    field_info = collection.fields().get(field, None)
    if field_info is None:
        return make_api_response("", f"Field '{field}' is not a valid field in bucket: {bucket}", 400)

    user = kwargs['user']
    fields = ["query", "mincount"]
    multi_fields = ['filters']

    if request.method == "POST":
        req_data = request.json
        params = {k: req_data.get(k, None) for k in fields if req_data.get(k, None) is not None}
        params.update({k: req_data.get(k, None) for k in multi_fields if req_data.get(k, None) is not None})

    else:
        req_data = request.args
        params = {k: req_data.get(k, None) for k in fields if req_data.get(k, None) is not None}
        params.update({k: req_data.getlist(k, None) for k in multi_fields if req_data.get(k, None) is not None})

    params.update({'access_control': user['access_control']})
    
    try:
        return make_api_response(collection.facet(field, **params))
    except SearchException as e:
        return make_api_response("", f"SearchException: {e}", 400)


@search_api.route("/histogram/<bucket>/<field>/", methods=["GET", "POST"])
@api_login(required_priv=['R'])
def histogram(bucket, field, **kwargs):
    """
    Generate an histogram based on a time or and int field using a specific gap size
    
    Variables:
    bucket       =>   Bucket to search in (alert, submission,...)
    field        =>   Field to generate the histogram from

    Optional Arguments:
    query        =>   Query to search for
    mincount     =>   Minimum item count for the fieldvalue to be returned
    filters      =>   Additional query to limit to output
    start        =>   Value at which to start creating the histogram
                       * Defaults: 0 or now-1d
    end          =>   Value at which to end the histogram
                       * Defaults: 2000 or now
    gap          =>   Size of each step in the histogram
                       * Defaults: 100 or +1h

    Data Block (POST ONLY):
    {"query": "id:*",
     "mincount": "10",
     "filters": ['fq'],
     "start": 0,
     "end": 100,
     "gap": 10}

    Result example:
    {                 # Histogram results
     "step_0": 2,
     ...
     "step_N": 19,
    }
    """
    fields = ["query", "mincount", "start", "end", "gap"]
    multi_fields = ['filters']
    user = kwargs['user']

    if bucket not in BUCKET_MAP:
        return make_api_response("", f"Not a valid bucket to search in: {bucket}", 400)
    collection = BUCKET_MAP[bucket]

    # Get fields default values
    field_info = collection.fields().get(field, None)
    if field_info is None:
        return make_api_response("", f"Field '{field}' is not a valid field in bucket: {bucket}", 400)
    elif field_info['type'] == "integer":
        params = {
            'start': 0,
            'end': 2000,
            'gap': 100
        }
    elif field_info['type'] == "date":
        params = {
            'start': f"{STORAGE.ds.now}-1{STORAGE.ds.day}",
            'end': f"{STORAGE.ds.now}",
            'gap': f"+1{STORAGE.ds.hour}"
        }
    else:
        err_msg = f"Field '{field}' is of type '{field_info['type']}'. Only 'integer' or 'date' are acceptable."
        return make_api_response("", err_msg, 400)

    # Load API variables
    if request.method == "POST":
        req_data = request.json
        params.update({k: req_data.get(k, None) for k in fields if req_data.get(k, None) is not None})
        params.update({k: req_data.get(k, None) for k in multi_fields if req_data.get(k, None) is not None})

    else:
        req_data = request.args
        params.update({k: req_data.get(k, None) for k in fields if req_data.get(k, None) is not None})
        params.update({k: req_data.getlist(k, None) for k in multi_fields if req_data.get(k, None) is not None})

    # Make sure access control is enforced
    params.update({'access_control': user['access_control']})

    try:
        return make_api_response(collection.histogram(field, **params))
    except SearchException as e:
        return make_api_response("", f"SearchException: {e}", 400)


@search_api.route("/stats/<bucket>/<int_field>/", methods=["GET", "POST"])
@api_login(required_priv=['R'])
def stats(bucket, int_field, **kwargs):
    """
    Perform statistical analysis of an integer field to get its min, max, average and count values

    Variables:
    bucket       =>   Bucket to search in (alert, submission,...)
    int_field    =>   Integer field to analyse

    Optional Arguments:
    query        =>   Query to search for
    filters      =>   Additional query to limit to output

    Data Block (POST ONLY):
    {"query": "id:*",
     "filters": ['fq']}

    Result example:
    {                 # Stats results
     "count": 1,        # Number of times this field is seen
     "min": 1,          # Minimum value
     "max": 1,          # Maximum value
     "avg": 1,          # Average value
     "sum": 1           # Sum of all values
    }
    """
    if bucket not in BUCKET_MAP:
        return make_api_response("", f"Not a valid bucket to search in: {bucket}", 400)
    collection = BUCKET_MAP[bucket]

    field_info = collection.fields().get(int_field, None)
    if field_info is None:
        return make_api_response("", f"Field '{int_field}' is not a valid field in bucket: {bucket}", 400)

    if field_info['type'] not in ["integer", "float"]:
        return make_api_response("", f"Field '{int_field}' is not a numeric field.", 400)

    user = kwargs['user']
    fields = ["query"]
    multi_fields = ['filters']

    if request.method == "POST":
        req_data = request.json
        params = {k: req_data.get(k, None) for k in fields if req_data.get(k, None) is not None}
        params.update({k: req_data.get(k, None) for k in multi_fields if req_data.get(k, None) is not None})

    else:
        req_data = request.args
        params = {k: req_data.get(k, None) for k in fields if req_data.get(k, None) is not None}
        params.update({k: req_data.getlist(k, None) for k in multi_fields if req_data.get(k, None) is not None})

    params.update({'access_control': user['access_control']})

    try:
        return make_api_response(collection.stats(int_field, **params))
    except SearchException as e:
        return make_api_response("", f"SearchException: {e}", 400)
