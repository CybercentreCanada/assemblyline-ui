import requests

from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint


SUB_API = 'feed'
feed_api = make_subapi_blueprint(SUB_API, api_version=4)
feed_api._doc = "Fetch feed to provided link"


@feed_api.route("/<url>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_feed_data(url, **kwargs):
    """
    Get and return the feed from the specified URL

    Variables:
    url         => to get the feed from

    Arguments:
    None

    Data Block:
    None

    Result example:
    <XML DATA>
    """
    try:
        return make_api_response(requests.get(url))
    except Exception as e:
        return make_api_response(None, f"An exception occured while fetching the feed: {e}", 400)
