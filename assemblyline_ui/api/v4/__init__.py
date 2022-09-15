from flask import current_app, Blueprint, request

from assemblyline_ui.api.base import api_login, make_api_response
from assemblyline_ui.config import config

API_PREFIX = "/api/v4"
apiv4 = Blueprint("apiv4", __name__, url_prefix=API_PREFIX)
apiv4._doc = "Version 4 Api Documentation"


#####################################
# API DOCUMENTATION
# noinspection PyProtectedMember,PyBroadException
@apiv4.route("/")
@api_login(audit=False, required_priv=['R', 'W'])
def get_api_documentation(**kwargs):
    """
    Full API doc.

    Loop through all registered API paths and display their documentation.
    Returns a list of API definition.

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    [                            # LIST of:
     {'name': "Api Doc",                # Name of the api
      'path': "/api/path/<variable>/",  # API path
      'ui_only': false,                 # Is UI only API
      'methods': ["GET", "POST"],       # Allowed HTTP methods
      'description': "API doc.",        # API documentation
      'id': "api_doc",                  # Unique ID for the API
      'function': "apiv4.api_doc",      # Function called in the code
      'protected': False,               # Does the API require login?
      'require_role': ['user'],         # Type of users allowed to use API
      'complete' : True},               # Is the API stable?
      ...]
    """
    user_roles = kwargs['user']['roles']

    api_blueprints = {}
    api_list = []
    for rule in current_app.url_map.iter_rules():
        if rule.rule.startswith(request.path):
            methods = []

            for item in rule.methods:
                if item != "OPTIONS" and item != "HEAD":
                    methods.append(item)

            func = current_app.view_functions[rule.endpoint]
            require_role = func.__dict__.get('require_role', [])
            allow_readonly = func.__dict__.get('allow_readonly', True)

            if config.ui.read_only and not allow_readonly:
                continue

            # Check role requirements
            allowed = not require_role
            if not allowed:
                for u_type in user_roles:
                    if u_type in require_role:
                        allowed = True
                        break

            if allowed:
                doc_string = func.__doc__
                func_title = " ".join([x.capitalize()
                                       for x in rule.endpoint[rule.endpoint.rindex(".") + 1:].split("_")])
                blueprint = rule.endpoint[:rule.endpoint.rindex(".")]
                if blueprint == "apiv4":
                    blueprint = "documentation"

                if blueprint not in api_blueprints:
                    try:
                        doc = current_app.blueprints[rule.endpoint[:rule.endpoint.rindex(".")]]._doc
                    except Exception:
                        doc = ""

                    api_blueprints[blueprint] = doc

                try:
                    description = "\n".join([x[4:] for x in doc_string.splitlines()])
                except Exception:
                    description = "[INCOMPLETE]\n\nTHIS API HAS NOT BEEN DOCUMENTED YET!"

                api_id = rule.endpoint.replace("apiv4.", "").replace(".", "_")

                api_list.append({
                    "protected": func.__dict__.get('protected', False),
                    "require_role": require_role,
                    "name": func_title,
                    "id": api_id,
                    "function": f"api.v4.{rule.endpoint}",
                    "path": rule.rule, "ui_only": rule.rule.startswith("%sui/" % request.path),
                    "methods": methods, "description": description,
                    "complete": "[INCOMPLETE]" not in description,
                    "required_priv": func.__dict__.get('required_priv', "")
                })

    return make_api_response({"apis": api_list, "blueprints": api_blueprints})
