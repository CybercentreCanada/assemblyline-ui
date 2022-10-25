import requests

from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import config

SUB_API = 'feed'
feed_api = make_subapi_blueprint(SUB_API, api_version=4)
feed_api._doc = "Fetch feed to provided link"


@feed_api.route("/", methods=["GET"])
@api_login(required_priv=['R'])
def get_feed_data(**_):
    """
    Get and return the feed from the specified URL

    Variables:
    url         => to get the feed from

    Arguments:
    None

    Data Block:
    None

    Result example:
    {"feeds": { url: <XML_DATA>}, "errors": []}
    """
    data = {"feeds": {}, "errors": {}}
    for feed in config.ui.rss_feeds:
        try:
            data["feeds"][feed] = requests.get(feed).content.decode('utf-8')
        except Exception as e:
            data["errors"][feed] = str(e)

    return make_api_response(data)
