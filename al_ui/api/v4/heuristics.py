
import concurrent.futures

from flask import request

from al_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from al_ui.config import STORAGE
from assemblyline.common import forge
from assemblyline.datastore import SearchException

Classification = forge.get_classification()

SUB_API = 'heuristics'
heuristics_api = make_subapi_blueprint(SUB_API)
heuristics_api._doc = "View the different heuristics of the system"


def get_stat_for_heuristic(p_id, p_classification):
    stats = STORAGE.result.stats("result.score",
                                 query=f"result.tags.value:{p_id} AND result.tags.type:HEURISTIC")
    if stats['count'] == 0:
        return {
            'heur_id': p_id,
            'classification': p_classification,
            'count': stats['count'],
            'min': 0,
            'max': 0,
            'avg': 0,
        }
    else:
        return {
            'heur_id': p_id,
            'classification': p_classification,
            'count': stats['count'],
            'min': int(stats['min']),
            'max': int(stats['max']),
            'avg': int(stats['avg']),
        }


@heuristics_api.route("/<heuristic_id>/", methods=["GET"])
@api_login(allow_readonly=False, required_priv=["R"])
def get_heuristic(heuristic_id, **kwargs):
    """
    Get a specific heuristic's detail from the system
    
    Variables:
    heuristic_id  => ID of the heuristic
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    {"id": "AL_HEUR_001",               # Heuristics ID
     "filetype": ".*",                  # Target file type
     "name": "HEURISTICS_NAME",         # Heuristics name
     "description": ""}                 # Heuristics description
    """
    user = kwargs['user']

    h = STORAGE.heuristic.get(heuristic_id, as_obj=False)

    if not h:
        return make_api_response("", "Heuristic not found", 404)


    if user and Classification.is_accessible(user['classification'], h['classification']):
        h.update(get_stat_for_heuristic(h['heur_id'], h['classification']))
        return make_api_response(h)
    else:
        return make_api_response("", "You are not allowed to see this heuristic...", 403)


@heuristics_api.route("/list/", methods=["GET"])
@api_login(allow_readonly=False, required_priv=["R"])
def list_heuritics(**kwargs):
    """
    List all heuristics in the system
    
    Variables:
    offset     =>  Offset to start returning results
    rows       =>  Number of results to return
    query      =>  Query to use to filter the results
    
    Arguments: 
    None
    
    Data Block:
    None

    API call example:
    /api/v3/heuristics/SW_HEUR_001/
    
    Result example:
    {"total": 201,                # Total heuristics found
     "offset": 0,                 # Offset in the heuristics list
     "rows": 100,                 # Number of heuristics returned
     "items": [{                  # List of heuristics
       "id": "AL_HEUR_001",               # Heuristics ID
       "filetype": ".*",                  # Target file type
       "name": "HEURISTICS_NAME",         # Heuristics name
       "description": ""                  # Heuristics description
     }, ... ]
    }
    """
    user = kwargs['user']
    offset = int(request.args.get('offset', 0))
    rows = int(request.args.get('rows', 100))
    query = request.args.get('query', "id:*") or "id:*"

    try:
        return make_api_response(STORAGE.heuristic.search(query, offset=offset, rows=rows,
                                                          access_control=user['access_control'], as_obj=False))
    except SearchException as e:
        return make_api_response("", f"SearchException: {e}", 400)


@heuristics_api.route("/stats/", methods=["GET"])
@api_login(allow_readonly=False)
def heuritics_statistics(**kwargs):
    """
    Gather all heuristics stats in system

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    [{"id": "AL_HEUR_001",          # Heuristics ID
       "count": "100",               # Count of times heuristics seen
       "min": 0,                     # Lowest score found
       "avg": 172,                   # Average of all scores
       "max": 780,                   # Highest score found
     }, ... ]
    """

    user = kwargs['user']

    heur_list = sorted([(x['heur_id'], x['classification'])
                       for x in STORAGE.heuristic.stream_search("heur_id:*", fl="heur_id,classification",
                                                                access_control=user['access_control'], as_obj=False)])

    with concurrent.futures.ThreadPoolExecutor(max(min(len(heur_list), 20), 1)) as executor:
        res = [executor.submit(get_stat_for_heuristic, heur_id, classification)
               for heur_id, classification in heur_list]

    return make_api_response(sorted([r.result() for r in res], key=lambda i: i['heur_id']))
