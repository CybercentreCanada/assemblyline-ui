
from assemblyline.common import forge
from al_ui.api.base import api_login, make_subapi_blueprint
from al_ui.api.v4 import authentication as v4_authentication

Classification = forge.get_classification()
API_PRIV_MAP = {
    "READ": ["R"],
    "READ_WRITE": ["R", "W"],
    "WRITE": ["W"]
}

SUB_API = 'auth'
auth_api = make_subapi_blueprint(SUB_API)
auth_api._doc = "Allow user to authenticate to the web server"


# noinspection PyBroadException,PyPropertyAccess
@auth_api.route("/login/", methods=["GET", "POST"])
def login(**_):
    """
    Login the user onto the system
    
    Variables:
    None
    
    Arguments: 
    None
    
    Data Block:
    {
     "user": <UID>,
     "password": <ENCRYPTED_PASSWORD>,
     "otp": <OTP_TOKEN>,
     "apikey": <ENCRYPTED_APIKEY>,
     "u2f_response": <RESPONSE_TO_CHALLENGE_FROM_U2F_TOKEN>
    }

    Result example:
    {
     "username": <Logged in user>, # Username for the logged in user
     "privileges": ["R", "W"],     # Different privileges that the user will get for this session
     "session_duration": 60        # Time after which this session becomes invalid
                                   #   Note: The timer reset after each call
    }
    """
    return v4_authentication.login(**_)


@auth_api.route("/logout/", methods=["GET"])
@api_login(audit=False, required_priv=['R', 'W'])
def logout(**_):
    """
    Logout from the system clearing the current session

    Variables:
    None

    Arguments: 
    None

    Data Block:
    None

    Result example:
    {
     "success": true
    }
    """
    return v4_authentication.logout(**_)
