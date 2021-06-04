
from assemblyline_ui.api.base import make_subapi_blueprint, make_api_response, api_login
from assemblyline_ui.config import STORAGE

SUB_API = 'whitelist'
whitelist_api = make_subapi_blueprint(SUB_API, api_version=4)
whitelist_api._doc = "Perform operations on whitelisted hashes"


@whitelist_api.route("/<sha256>/", methods=["GET"])
@api_login()
def exists(sha256, **_):
    """
    Check if a hash exists in the whitelist.

    Variables:
    sha256       => Hash to check

    Arguments:
    None

    Data Block:
    None

    API call example:
    GET /api/v1/whitelist/123456...654321/

    Result example:
    <Whitelisting object>
    """
    whitelist = STORAGE.whitelist.get_if_exists(sha256, as_obj=False)
    if whitelist:
        return make_api_response(whitelist)

    return make_api_response(None, "The hash was not found in the whitelist.", 404)
