
from al_ui.api.base import api_login, make_subapi_blueprint
from al_ui.api.v4 import user as v4_user

SUB_API = 'user'
user_api = make_subapi_blueprint(SUB_API)
user_api._doc = "Manage the different users of the system"


######################################################
# User's default submission parameters
######################################################

@user_api.route("/submission_params/<username>/", methods=["GET"])
@api_login(audit=False, required_priv=['R', 'W'])
def get_user_submission_params(username, **kwargs):
    """
    Load the user's default submission params that should be passed to the submit API.
    This is mainly use so you can alter a couple fields and preserve the user
    default values.

    Variables:
    username    => Name of the user you want to get the settings for

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
     "profile": true,               # Should submissions be profiled
     "classification": "",          # Default classification for this user sumbissions
     "description": "",             # Default description for this user's submissions
     "priority": 1000,              # Default submission priority
     "service_spec": [],            # Default Service specific parameters
     "ignore_cache": true,          # Should file be reprocessed even if there are cached results
     "groups": [ ... ],             # Default groups selection for the user scans
     "ttl": 30,                     # Default time to live in days of the users submissions
     "services": [ ... ],           # Default list of selected services
     "ignore_filtering": false      # Should filtering services by ignored?
    }
    """
    return v4_user.get_user_submission_params(username, **kwargs)
