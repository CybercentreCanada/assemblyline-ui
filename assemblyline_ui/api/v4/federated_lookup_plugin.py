"""Federated Lookup

Lookup related data from external systems. Data could include:

* IOCs
* Hashes
* Others?


TODO Questions:
* dynamic module loading, or config based?
    module loading will look cleaner and easier to abstract away, but add complexity
    config loading will probably be less complex, but the config itself will be large and complex
* should users be required to have an account on the upstream system and then lookup on behalf of?

"""
import pkg_resources

from urllib import parse as ul
from flask import request

from assemblyline.odm.models.user import ROLES
from assemblyline_ui.api.base import api_login, make_subapi_blueprint
from assemblyline_ui.config import CLASSIFICATION as Classification
from assemblyline_ui.helper.federated_lookup import FederatedLookupBase


SUB_API = "federated_lookup"
federated_lookup_api = make_subapi_blueprint(SUB_API, api_version=4)
federated_lookup_api._doc = "Lookup related data through configured external data sources/systems."

# Search the configured entry points and load the defined federated searches."""
loaded_sources = sorted(
    [(ep.name, ep.load()) for ep in pkg_resources.iter_entry_points("assemblyline_ui.federated_lookup")],
    key=lambda x: x[0]
)


# I don't like ioc as a name, perhaps tags is more approporiate?
# but there may not be a 1:1 mapping of AL tag name to external system "tag" name, which might be confusing
@federated_lookup_api.route("/ioc/<indicator_type>/<ioc>/", methods=["GET"])
@api_login(require_role=[ROLES.alert_view, ROLES.submission_view])
def search_ioc(indicator_type: str, ioc: str, **kwargs) -> dict[str, list[dict[str, str]]]:
    """
    Search for an Indicator of Compromise across all configured external sources/systems.

    Variables:
    indicator_type => define the type of indicator that is being looked up
    ioc => IOC to lookup. Must be URL encoded.

    Arguments:(optional)
    max_timeout => Maximum execution time for the call in seconds [Default: 3 seconds]
    sources     => | separated list of data sources [Default: all]
    limit       => limit the amount of returned results [Default: 5]

    Data Block:
    None

    API call examples:
    /api/v4/federated_lookup/url/http%3A%2F%2Fmalicious.domain%2Fbad/
    /api/v4/federated_lookup/url/http%3A%2F%2Fmalicious.domain%2Fbad/?sources=virustotal|malware_bazar

    Returns:
    A dictionary of sources with links to found samples.

    Result example:
    {                           # Dictionary of:
        <source_name>: [
            {<name>: <https link to results>},
            ...,
        ],
        ...,
    }
    """

    user = kwargs['user']
    sources = request.args.get("sources", "all")

    max_timeout = request.args.get('max_timeout', "3")
    limit = request.args.get('limit', "3")
    # noinspection PyBroadException
    try:
        max_timeout = float(max_timeout)
    except Exception:
        max_timeout = 3.0

    links = {}
    for package_name, SourceLookup in loaded_sources:
        if sources == "all" or package_name in sources:
            # ensure all lookups implement the correct interface
            if not isinstance(SourceLookup, FederatedLookupBase):
                continue
            external = SourceLookup(max_timeout=max_timeout, limit=limit)

            # perform the lookup, ensuring access controls are applied
            res = external.lookup_ioc(ul.unquote_plus(ioc), indicator_type)
            if res is None:
                # None is expected for both not found and for any errors.
                # as we query across multiple sources, errors should be skipped?
                continue
            for name, details in res.items():
                if user and Classification.is_accessible(user['classification'], details['classification']):
                    links.setdefault(package_name, []).append({name: details["link"]})
    return links
