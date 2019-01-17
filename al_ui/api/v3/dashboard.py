
import concurrent.futures

from assemblyline.al.service.list_queue_sizes import get_service_queue_length
from al_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from al_ui.config import config, STORAGE

SUB_API = 'dashboard'
dashboard_api = make_subapi_blueprint(SUB_API)
dashboard_api._doc = "Display systems health"

EXPIRY_BUCKET_LIST = ["submission", "file", "alert", "result", "error", "filescore"]

###########################################################################
# Dashboard APIs


@dashboard_api.route("/expiry/", methods=["GET"])
@api_login(audit=False, allow_readonly=False)
def get_expiry_(**_):
    """
    Check each buckets to make sure they don't have expired data that remains.
    Returns 'true' for each bucket that is fully expired.

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
      "submission": true,
      "file": false,
      ...
    }
    """
    def run_query(bucket):
        return STORAGE.direct_search(bucket, "__expiry_ts__:[NOW/DAY TO NOW/DAY-2DAY]",
                                     args=[("rows", "0"), ("timeAllowed", "500")])['response']['numFound'] == 0

    with concurrent.futures.ThreadPoolExecutor(len(EXPIRY_BUCKET_LIST)) as executor:
        res = {b: executor.submit(run_query, b) for b in EXPIRY_BUCKET_LIST}

    return make_api_response({k: v.result() for k, v in res})


@dashboard_api.route("/queues/", methods=["GET"])
@api_login(audit=False, allow_readonly=False)
def list_queue_sizes(**_):
    """
    List services queue size for each services in the system.
    
    Variables:
    None
    
    Arguments:
    None
    
    Data Block:
    None
    
    Result example:
    {"MY SERVICE": 1, ... } # Dictionnary of services and number item in queue
    """
    services = list(set([s.get("classpath", None) for s in STORAGE.list_services()]))
    queue_lengths = {}
    for svc in services:
        queue_lengths[svc.split(".")[-1]] = get_service_queue_length(svc)

    return make_api_response(queue_lengths)


@dashboard_api.route("/services/", methods=["GET"])
@api_login(audit=False, allow_readonly=False)
def list_services_workers(**_):
    """
    List number of workers for each services in the system.
    
    Variables:
    None
    
    Arguments:
    None
    
    Data Block:
    None
    
    Result example:
    {
     "SRV_NAME": {        # Single service overview
       "enabled": True,     # is enabled?
       "queue": 0,          # items in queue
       "workers": 1         # minimum number of workers to be provisionned
     },
    }
    """
    services = {s["name"]: {"enabled": s["enabled"],
                            "queue": 0,
                            "workers": config.core.orchestrator.min_service_workers}
                for s in STORAGE.list_services()}

    for srv in services:
        services[srv]["queue"] = get_service_queue_length(srv)

    return make_api_response(services)


@dashboard_api.route("/shards/", methods=["GET"])
@api_login(audit=False, allow_readonly=False)
def get_expected_shard_count(**_):
    """
    Get the number of dispatcher shards that are 
    supposed to be running in the system
    
    Variables:
    None
    
    Arguments:
    None
    
    Data Block:
    None
    
    Result example:
    1         # Number of shards
    """
    return make_api_response({
        'dispatcher': config.core.dispatcher.shards,
        'middleman': config.core.middleman.shards,
    })
