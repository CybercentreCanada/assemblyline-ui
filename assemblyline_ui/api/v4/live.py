
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import STORAGE, CLASSIFICATION as Classification
from assemblyline.remote.datatypes.queues.named import NamedQueue
from assemblyline.odm.models.user import ROLES
from assemblyline_core.dispatching.client import DispatchClient

SUB_API = 'live'
live_api = make_subapi_blueprint(SUB_API, api_version=4)
live_api._doc = "Interact with live processing messages"


@live_api.route("/get_message/<wq_id>/", methods=["GET"])
@api_login(audit=False, allow_readonly=False, require_role=[ROLES.submission_view])
def get_message(wq_id, **_):
    """
    Get a message from a live watch queue.
    Note: This method is not optimal because it requires the
          UI to pull the information. The prefered method is the
          socket server.

    Variables:
    wq_id       => Queue to get the message from

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
     "type": "",         # Type of message
     "err_msg": "",      # Error message
     "status_code": 400, # Status code of the error
     "msg": ""           # Message
    }
    """
    msg = NamedQueue(wq_id).pop(blocking=False)

    if msg is None:
        response = {'type': 'timeout', 'err_msg': 'Timeout waiting for a message.', 'status_code': 408, 'msg': None}
    elif msg['status'] == 'STOP':
        response = {'type': 'stop', 'err_msg': None, 'status_code': 200,
                    'msg': "All messages received, closing queue..."}
    elif msg['status'] == 'START':
        response = {'type': 'start', 'err_msg': None, 'status_code': 200, 'msg': "Start listening..."}
    elif msg['status'] == 'OK':
        response = {'type': 'cachekey', 'err_msg': None, 'status_code': 200, 'msg': msg['cache_key']}
    elif msg['status'] == 'FAIL':
        response = {'type': 'cachekeyerr', 'err_msg': None, 'status_code': 200, 'msg': msg['cache_key']}
    else:
        response = {'type': 'error', 'err_msg': "Unknown message", 'status_code': 400, 'msg': msg}

    return make_api_response(response)


@live_api.route("/get_message_list/<wq_id>/", methods=["GET"])
@api_login(audit=False, allow_readonly=False, require_role=[ROLES.submission_view])
def get_messages(wq_id, **_):
    """
    Get all messages currently on a watch queue.
    Note: This method is not optimal because it requires the
          UI to pull the information. The prefered method is the
          socket server when possible.

    Variables:
    wq_id       => Queue to get the message from

    Arguments:
    None

    Data Block:
    None

    Result example:
    []            # List of messages
    """
    resp_list = []
    u = NamedQueue(wq_id)

    while True:
        msg = u.pop(blocking=False)
        if msg is None:
            break

        elif msg['status'] == 'STOP':
            response = {'type': 'stop', 'err_msg': None, 'status_code': 200,
                        'msg': "All messages received, closing queue..."}
        elif msg['status'] == 'START':
            response = {'type': 'start', 'err_msg': None, 'status_code': 200, 'msg': "Start listening..."}
        elif msg['status'] == 'OK':
            response = {'type': 'cachekey', 'err_msg': None, 'status_code': 200, 'msg': msg['cache_key']}
        elif msg['status'] == 'FAIL':
            response = {'type': 'cachekeyerr', 'err_msg': None, 'status_code': 200, 'msg': msg['cache_key']}
        else:
            response = {'type': 'error', 'err_msg': "Unknown message", 'status_code': 400, 'msg': msg}

        resp_list.append(response)

    return make_api_response(resp_list)


@live_api.route("/outstanding_services/<sid>/", methods=["GET"])
@api_login(audit=False, allow_readonly=False, require_role=[ROLES.submission_view])
def outstanding_services(sid, **kwargs):
    """
    List outstanding services and the number of file each
    of them still have to process.

    Variables:
    sid      => Submission ID

    Arguments:
    None

    Data Block:
    None

    Result example:
    {"MY SERVICE": 1, ... } # Dictionnary of services and number of files
    """
    data = STORAGE.submission.get(sid, as_obj=False)
    user = kwargs['user']

    if user and data and Classification.is_accessible(user['classification'], data['classification']):
        return make_api_response(DispatchClient(datastore=STORAGE).outstanding_services(sid))
    else:
        return make_api_response({}, "You are not allowed to access this submissions.", 403)


@live_api.route("/setup_watch_queue/<sid>/", methods=["GET"])
@api_login(audit=False, allow_readonly=False, require_role=[ROLES.submission_view])
def setup_watch_queue(sid, **kwargs):
    """
    Starts a watch queue to get live results

    Variables:
    sid      => Submission ID

    Arguments:
    None

    Data Block:
    None

    Result example:
    {"wq_id": "D-c7668cfa-...-c4132285142e-WQ"} #ID of the watch queue
    """
    data = STORAGE.submission.get(sid, as_obj=False)
    user = kwargs['user']

    if user and data and Classification.is_accessible(user['classification'], data['classification']):
        wq_id = DispatchClient(datastore=STORAGE).setup_watch_queue(sid)
        if wq_id:
            return make_api_response({"wq_id": wq_id})
        return make_api_response("", "No dispatchers are processing this submission.", 404)
    else:
        return make_api_response("", "You are not allowed to access this submissions.", 403)
