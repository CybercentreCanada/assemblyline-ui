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
@api_login(audit=False, required_priv=['R', 'W'],
           require_type=["user", "signature_importer", "signature_manager", "admin"])
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
      'require_type': ['user'],         # Type of users allowed to use API
      'complete' : True},               # Is the API stable?
      ...]
    """
    user_types = kwargs['user']['type']

    api_blueprints = {}
    api_list = []
    for rule in current_app.url_map.iter_rules():
        if rule.rule.startswith(request.path):
            methods = []

            for item in rule.methods:
                if item != "OPTIONS" and item != "HEAD":
                    methods.append(item)

            func = current_app.view_functions[rule.endpoint]
            require_type = func.__dict__.get('require_type', ['user'])
            allow_readonly = func.__dict__.get('allow_readonly', True)

            if config.ui.read_only and not allow_readonly:
                continue

            for u_type in user_types:
                if u_type in require_type:
                    doc_string = func.__doc__
                    func_title = " ".join([x.capitalize()
                                           for x in rule.endpoint[rule.endpoint.rindex(".") + 1:].split("_")])
                    blueprint = rule.endpoint[rule.endpoint.index(".") + 1:rule.endpoint.rindex(".")]
                    if not blueprint:
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

                    if rule.endpoint == "apiv4.api_doc":
                        api_id = "documentation_api_doc"
                    else:
                        api_id = rule.endpoint.replace("apiv4.", "").replace(".", "_")

                    api_list.append({
                        "protected": func.__dict__.get('protected', False),
                        "require_type": require_type,
                        "name": func_title,
                        "id": api_id,
                        "function": rule.endpoint,
                        "path": rule.rule, "ui_only": rule.rule.startswith("%sui/" % request.path),
                        "methods": methods, "description": description,
                        "complete": "[INCOMPLETE]" not in description,
                        "required_priv": func.__dict__.get('required_priv', "")
                    })

                    break

    return make_api_response({"apis": api_list, "blueprints": api_blueprints})
