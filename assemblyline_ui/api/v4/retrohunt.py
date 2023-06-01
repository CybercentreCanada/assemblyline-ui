import hauntedhouse
import typing
from flask import request

from assemblyline.common.chunk import chunk
from assemblyline.odm.models.user import ROLES
from assemblyline.odm.models.retrohunt import Retrohunt
from assemblyline.datastore.collection import Index
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import STORAGE, config, CLASSIFICATION

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


def prepare_search_result_detail(api_result: typing.Optional[hauntedhouse.SearchStatus], datastore_result: dict,
                                 user_access, offset=0, rows=50):
    if api_result:
        selected_hashes = api_result.hits[offset:offset+rows]
        errors = api_result.errors
        truncated = api_result.truncated
        total_hits = len(api_result.hits)
    else:
        selected_hashes = datastore_result['hits'][offset:offset+rows]
        errors = datastore_result['errors']
        truncated = datastore_result['truncated']
        total_hits = datastore_result['total_hits']

    # supplement file information
    hits = []
    for batch in chunk(selected_hashes, 1000):
        for doc in STORAGE.file.multiget(batch, as_obj=False, error_on_missing=False,
                                         as_dictionary=False, index_type=Index.HOT_AND_ARCHIVE):
            if CLASSIFICATION.is_accessible(user_access, doc['classification']):
                hits.append(doc)

    # Mix togeather the documents from the two information sources
    datastore_result.update({
        'errors': errors,
        'hits': hits,
        'total_hits': total_hits,
        'finished': True if api_result is None else is_finished(api_result),
        'truncated': truncated,
    })
    return datastore_result


@retrohunt_api.route("/", methods=["POST"])
@api_login(require_role=[ROLES.retrohunt_run])
def create(**kwargs):
    """
    Create a new search over file storage.

    Arguments:
        yara_signature => yara signature to search with
        archive_only => Should the search only be run on archived files
        description => Textual description of this search
        classification => Classification level for the search

    Response should always be the same as polling the details of the search.
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
        'creator': user['uname'],
        'tags': {},
        'description': description,
        'classification': classification,
        'yara_signature': signature,
        'raw_query': hauntedhouse.client.query_from_yara(signature),
        'code': status.code,
        'finished': False,
        'hits': [],
        'errors': [],
    }).as_primitives()

    STORAGE.retrohunt.save(status.code, doc)
    return make_api_response(prepare_search_result_detail(status, doc, user['classification'], offset=0, limit=100))


@retrohunt_api.route("/<code>/", methods=["GET"])
@api_login(require_role=[ROLES.retrohunt_view])
def detail(code, **kwargs):
    """
    Get details about a completed or in progress retrohunt search.

    Variables:
        code                => Search code to be retrieved

    Parameters:
        offset              => how far into the hit set to return details for
        rows                => how many rows to return details for

    Response Fields:
        code                => unique code identifying this search request
        creator             => user who created this search
        tags                => tags describing this search
        description         => human readable description of search
        created             => timestamp when search started
        classification      => classification string for search and results list
        yara_signature      => text of original yara signature run
        raw_query           => text of filter query derived from yara signature

        errors              => a list of error messages accumulated
        hits                => list of dicts with information about what the search hit on
        total_hits
        offset
        finished            => boolean indicating if the search is finished
        truncated           => boolean has the list of hits been truncated at some limit
    """
    user = kwargs['user']
    offset = int(request.args.get('offset', '0'))
    rows = int(request.args.get('rows', '50'))

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
            doc['truncated'] = status.truncated
            doc['hits'] = status.hits
            doc['errors'] = status.errors
            doc['total_hits'] = len(status.hits)
            doc['finished'] = True
            STORAGE.retrohunt.save(code, doc)

    return make_api_response(prepare_search_result_detail(status, doc, user['classification'],
                                                          offset=offset, rows=rows))
