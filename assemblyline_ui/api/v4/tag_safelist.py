
from assemblyline.datastore.exceptions import SearchException
from flask import request

from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import STORAGE

SUB_API = 'tag_safelist'
tag_safelist_api = make_subapi_blueprint(SUB_API, api_version=4)
tag_safelist_api._doc = "Perform operations on safelisted hashes"


@tag_safelist_api.route("/", methods=["PUT"])
@api_login(require_type=['admin'], allow_readonly=False, required_priv=["W"])
def add_to_tag_safelist(**kwargs):
    """
    Add to system tag safelist

    Arguments:
    None

    Data Block:
    {
     <TBD>
    }

    Result example:
    {
     "success": true,         # Was the tag safelist successfully added
    }
    """
    # Load data
    data = request.json
    if not data:
        return make_api_response({}, "No data provided", 400)

    return make_api_response({"success": True})


@tag_safelist_api.route("/<tag_id>/", methods=["GET"])
@api_login(require_type=['admin'], required_priv=['R'])
def get_tag_safelist(tag_id, **_):
    """
    Get the details of a tag safelist item

    Variables:
    tag_id         => Id of the tag to get

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
        TBD
    }
    """
    return make_api_response(STORAGE.tag_safelist.get(tag_id, as_obj=False))


@tag_safelist_api.route("/list/", methods=["GET"])
@api_login(require_type=['admin'])
def list_tag_safelist(**_):
    """
    List all tag safelist items (per page)

    Variables:
    None

    Arguments:
    offset       => Offset at which we start giving tag safelists
    query        => Query to apply to the tag safelist
    rows         => Numbers of tags to return
    sort         => Sort order

    Data Block:
    None

    Result example:
    {"total": 201,                # Total tags found
     "offset": 0,                 # Offset in the tag safelist
     "count": 100,                # Number of tags returned
     "items": []                  # List of tag safelist blocks
    }
    """
    offset = int(request.args.get('offset', 0))
    rows = int(request.args.get('rows', 100))
    query = request.args.get('query', "id:*") or "id:*"
    sort = request.args.get('sort', "created desc")

    try:
        return make_api_response(STORAGE.tag_safelist.search(query, offset=offset, rows=rows, as_obj=False,
                                                             sort=sort))
    except SearchException as e:
        return make_api_response("", f"The specified search query is not valid. ({e})", 400)


@tag_safelist_api.route("/<tag_id>/", methods=["POST"])
@api_login(require_type=['admin'], allow_readonly=False, required_priv=["W"])
def update_tag_in_safelist(tag_id, **kwargs):
    """
    Update a system tag safelist

    Arguments:
    None

    Data Block:
    {
     <TBD>
    }

    Result example:
    {
     "success": true,         # Was the tag safelist successfully added
    }
    """
    # Load data
    data = request.json
    if not data:
        return make_api_response({}, "No data provided", 400)

    return make_api_response({"success": True})


@tag_safelist_api.route("/<tag_id>/", methods=["DELETE"])
@api_login(require_type=['admin'], allow_readonly=False, required_priv=["W"])
def delete_hash(tag_id, **_):
    """
    Delete a system tag from the safelist

    Variables:
    tag_id       => tag id to delete

    Arguments:
    None

    Data Block:
    None

    API call example:
    DELETE /api/v1/tag_safelist/123456...654321/

    Result example:
    {"success": True}
    """
    return make_api_response({'success': STORAGE.safelist.delete(tag_id)})
