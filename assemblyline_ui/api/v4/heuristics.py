
import concurrent.futures


from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import STORAGE
from assemblyline.common import forge

Classification = forge.get_classification()

SUB_API = 'heuristics'
heuristics_api = make_subapi_blueprint(SUB_API, api_version=4)
heuristics_api._doc = "View the different heuristics of the system"


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
        h.update(STORAGE.get_stat_for_heuristic(h['heur_id'], h['name'], h['classification']))
        return make_api_response(h)
    else:
        return make_api_response("", "You are not allowed to see this heuristic...", 403)


@heuristics_api.route("/stats/", methods=["GET"])
@api_login(required_priv=['R'], allow_readonly=False)
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

    stats = forge.get_statistics_cache().get('heuristics') or []

    return make_api_response([x for x in stats
                              if Classification.is_accessible(user['classification'], x['classification'])])
