
from assemblyline_core.replay.client import REPLAY_PENDING, REPLAY_DONE, REPLAY_REQUESTED
from assemblyline_ui.config import STORAGE, CLASSIFICATION as Classification, REPLAY_ALERT_QUEUE, REPLAY_FILE_QUEUE, \
    REPLAY_SUBMISSION_QUEUE
from flask import request

from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint

SUB_API = 'replay'
replay_api = make_subapi_blueprint(SUB_API, api_version=4)
replay_api._doc = "API specific to the Replay feature"

QUEUE_MAP = {
    'alert': REPLAY_ALERT_QUEUE,
    'file': REPLAY_FILE_QUEUE,
    'submission': REPLAY_SUBMISSION_QUEUE
}


@replay_api.route("/queue/<message_type>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_message(message_type, **_):
    """
    Read a message from the queue

    Variables:
    message_type         =>    Type of message (file | submission | alert)

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
        ...  # Message from the queue
    }
    """
    if message_type not in ['file', 'submission', 'alert']:
        return make_api_response("", f"{message_type.upper()} is not a valid message type for this API.", 400)

    return make_api_response(QUEUE_MAP[message_type].pop(blocking=True, timeout=30))


@replay_api.route("/queue/<message_type>/", methods=["PUT"])
@api_login(required_priv=['W'])
def put_message(message_type, **_):
    """
    Put a message in a queue for processing in a worker

    Variables:
    message_type         =>    Type of message (file | submission | alert)

    Arguments:
    None

    Data Block:
    {
        ...  # Message to put in the queue
    }

    Result example:
    {"success": true}
    """
    if message_type not in ['file', 'submission', 'alert']:
        return make_api_response("", f"{message_type.upper()} is not a valid message type for this API.", 400)

    message = request.json
    if (message_type == 'alert' and sorted(message.keys()) == ["alert_id", "reporting_ts"]):
        QUEUE_MAP[message_type].push(message)
    elif (message_type == 'submission' and sorted(message.keys()) == ["sid", "times"]):
        QUEUE_MAP[message_type].push(message)
    elif (message_type == 'file' and isinstance(message, str)):
        QUEUE_MAP[message_type].push(message)
    else:
        return make_api_response("", f"Invalid message for type {message_type.upper()}: {message}", 400)

    return make_api_response({'success': True})


@replay_api.route("/<index>/<doc_id>/", methods=["GET"])
@api_login(audit=True, required_priv=['W'])
def request_replay(index, doc_id, **kwargs):
    """
    Request an alert or a submission to be transfered to another system

    Variables:
    index         =>    Type of document to be transfered (alert or submission)
    doc_id        =>    ID of the document to transfer

    Arguments:
    None

    Data Block:
    None

    Result example:
    {"success": true}
    """
    user = kwargs['user']

    if index not in ['alert', 'submission']:
        return make_api_response("", f"{index.upper()} is not a valid index for this API.", 400)

    index_ds = STORAGE.get_collection(index)
    doc = index_ds.get_if_exists(doc_id, as_obj=False)
    if not doc or not Classification.is_accessible(user['classification'], doc['classification']):
        return make_api_response("", f"You are not allowed to modify the {index} with the following ID: {doc_id}", 403)

    operations = [(index_ds.UPDATE_SET, 'metadata.replay', REPLAY_REQUESTED)]
    return make_api_response({
        'success': index_ds.update(doc_id, operations)
    })


@replay_api.route("/<index>/<doc_id>/", methods=["POST"])
@api_login(audit=True, required_priv=['W'])
def set_replay_complete(index, doc_id, **kwargs):
    """
    Mark an alert or submission successfully transfered to another system

    Variables:
    index         =>    Type of document transfered (alert or submission)
    doc_id        =>    ID of the document transfered

    Arguments:
    None

    Data Block:
    None

    Result example:
    {"success": true}
    """
    user = kwargs['user']

    if index not in ['alert', 'submission']:
        return make_api_response("", f"{index.upper()} is not a valid index for this API.", 400)

    index_ds = STORAGE.get_collection(index)
    doc = index_ds.get_if_exists(doc_id, as_obj=False)
    if not doc or not Classification.is_accessible(user['classification'], doc['classification']):
        return make_api_response("", f"You are not allowed to modify the {index} with the following ID: {doc_id}", 403)

    operations = [(index_ds.UPDATE_SET, 'metadata.replay', REPLAY_DONE)]
    return make_api_response({
        'success': index_ds.update(doc_id, operations)
    })


@replay_api.route("/pending/", methods=["POST"])
@api_login(audit=False, required_priv=['W'])
def set_bulk_replay_pending(**kwargs):
    """
    Set the replay pending state on alert or submissions maching the queries

    Variables:
    None

    Arguments:
    None

    Data Block:
    {
     "index": "alert",      # Target index (alert or submission)
     "query": "*:*",        # Main query
     "filter_queries": [],  # List of filter queries
     "max_docs": 100        # Maximum amount of document to change
    }

    Result example:
    {"success": true}
    """
    user = kwargs['user']
    data = request.json

    index = data.get('index', None)
    query = data.get('query', None)
    fqs = data.get('filter_queries', None)
    max_docs = data.get('max_docs', None)

    if index is None or query is None or fqs is None or max_docs is None:
        return make_api_response("", "Invalid data block.", 400)

    if index not in ['alert', 'submission']:
        return make_api_response("", f"{index.upper()} is not a valid index for this API.", 400)

    index_ds = STORAGE.get_collection(index)
    operations = [(index_ds.UPDATE_SET, 'metadata.replay', REPLAY_PENDING)]
    return make_api_response({
        'success': True,
        "count": index_ds.update_by_query(query, operations, filters=fqs,
                                          max_docs=max_docs, access_control=user['access_control'])
    })
