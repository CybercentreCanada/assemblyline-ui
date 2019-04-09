import os
import base64
import baseconv
import shutil
import uuid

from flask import request

from al_ui.helper.service import ui_to_submission_params
from assemblyline.common import forge, identify
from assemblyline.common.isotime import now_as_iso
from assemblyline.odm.messages.submission import Submission
from assemblyline.remote.datatypes.queues.named import NamedQueue
from al_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from al_ui.config import TEMP_SUBMIT_DIR, STORAGE, config
from al_ui.helper.submission import safe_download, FileTooBigException, InvalidUrlException, ForbiddenLocation
from al_ui.helper.user import get_default_user_settings

SUB_API = 'ingest'
ingest_api = make_subapi_blueprint(SUB_API, api_version=4)
ingest_api._doc = "Ingest files for large volume processing"

ingest = NamedQueue(
    "m-ingest",
    host=config.core.redis.persistent.host,
    port=config.core.redis.persistent.port,
    db=config.core.redis.persistent.db)


# noinspection PyUnusedLocal
@ingest_api.route("/get_message/<notification_queue>/", methods=["GET"])
@api_login(required_priv=['R'], allow_readonly=False)
def get_message(notification_queue, **kwargs):
    """
    Get one message on the specified notification queue

    Variables:
    complete_queue       => Queue to get the message from

    Arguments:
    None

    Data Block:
    None

    Result example:
    {}          # A message
    """
    u = NamedQueue("nq-%s" % notification_queue,
                   host=config.core.redis.persistent.host,
                   port=config.core.redis.persistent.port,
                   db=config.core.redis.persistent.db)

    msg = u.pop(blocking=False)

    return make_api_response(msg)


# noinspection PyUnusedLocal
@ingest_api.route("/get_message_list/<notification_queue>/", methods=["GET"])
@api_login(required_priv=['R'], allow_readonly=False)
def get_all_messages(notification_queue, **kwargs):
    """
    Get all messages on the specified notification queue

    Variables:
    complete_queue       => Queue to get the message from

    Arguments:
    None

    Data Block:
    None

    Result example:
    []            # List of messages
    """
    resp_list = []
    u = NamedQueue("nq-%s" % notification_queue,
                   host=config.core.redis.persistent.host,
                   port=config.core.redis.persistent.port,
                   db=config.core.redis.persistent.db)

    while True:
        msg = u.pop(blocking=False)

        if msg is None:
            break

        resp_list.append(msg)

    return make_api_response(resp_list)


# noinspection PyBroadException
@ingest_api.route("/", methods=["POST"])
@api_login(required_priv=['W'], allow_readonly=False)
def ingest_single_file(**kwargs):
    """
    Ingest a single file in the system

        Note:
            * Binary, sha256 and url fields are optional but at least one of them has to be there
            * notification_queue, notification_threshold and generate_alert fields are optional

        Note 2:
            The ingest API uses the user's default settings to submit files to the system
            unless these settings are overridden in the 'params' field. Although, there are
            exceptions to that rule. Fields deep_scan, ignore_filtering, ignore_cache are
            resetted to False because the lead to dangerous behavior in the system.

    Variables:
    None

    Arguments:
    None

    Data Block:
    {
     "name": "file.exe",             # Name of the file
     "binary": "A24AB..==",          # Base64 encoded file binary
     "sha256": "1234...CDEF"         # SHA256 hash of the file
     "url": "http://...",            # Url to fetch the file from

     "metadata": {                   # Submission Metadata
         "key": val,                    # Key/Value pair for metadata parameters
         },

     "params": {                     # Submission parameters
         "key": val,                    # Key/Value pair for params that differ from the user's defaults
         },                                 # DEFAULT: /api/v3/user/submission_params/<user>/

     "generate_alert": False,        # Generate an alert in our alerting system or not
     "notification_queue": None,     # Name of the notification queue
     "notification_threshold": None, # Threshold for notification
    }

    Result example:
    { "success": true }
    """
    user = kwargs['user']
    out_dir = os.path.join(TEMP_SUBMIT_DIR, baseconv.base62.encode(uuid.uuid4().int))
    with forge.get_filestore() as f_transport:
        try:
            # Get data block
            data = request.json
            if not data:
                return make_api_response({}, "Missing data block", 400)

            # Get notification queue parameters
            notification_queue = data.get('notification_queue', None)
            if notification_queue:
                notification_queue = "nq-%s" % notification_queue

            notification_threshold = data.get('notification_threshold', None)
            if not isinstance(notification_threshold, int) and notification_threshold:
                return make_api_response({}, "notification_threshold should be and int", 400)

            # Get generate alert parameter
            generate_alert = data.get('generate_alert', False)
            if not isinstance(generate_alert, bool):
                return make_api_response({}, "generate_alert should be a boolean", 400)

            # Get file name
            name = data.get("name", None)
            if not name:
                return make_api_response({}, "Filename missing", 400)

            name = os.path.basename(name)
            if not name:
                return make_api_response({}, "Invalid filename", 400)

            out_file = os.path.join(out_dir, name)

            try:
                os.makedirs(out_dir)
            except Exception:
                pass

            # Load file
            binary = data.get("binary", None)
            if not binary:
                sha256 = data.get('sha256', None)
                if sha256:
                    if f_transport.exists(sha256):
                        f_transport.download(sha256, out_file)
                    else:
                        return make_api_response({}, "SHA256 does not exist in our datastore", 404)
                else:
                    url = data.get('url', None)
                    if url:
                        if not config.ui.allow_url_submissions:
                            return make_api_response({}, "URL submissions are disabled in this system", 400)

                        try:
                            safe_download(url, out_file)
                        except FileTooBigException:
                            return make_api_response({}, "File too big to be scanned.", 400)
                        except InvalidUrlException:
                            return make_api_response({}, "Url provided is invalid.", 400)
                        except ForbiddenLocation:
                            return make_api_response({}, "Hostname in this URL cannot be resolved.", 400)
                    else:
                        return make_api_response({}, "Missing file to scan. No binary, sha256 or url provided.", 400)
            else:
                with open(out_file, "wb") as my_file:
                    my_file.write(base64.b64decode(binary))

            # Load default user params
            s_params = ui_to_submission_params(STORAGE.user_settings.get(user['uname'], as_obj=False))
            if not s_params:
                s_params = get_default_user_settings(user)

            # Reset dangerous user settings to safe values
            s_params.update({
                'deep_scan': False,
                "priority": 150,
                "ignore_cache": False,
                "ignore_dynamic_recursion_prevention": False,
                "ignore_filtering": False,
                "type": "INGEST"
            })

            # Apply provided params
            s_params.update(data.get("params", {}))

            # Override final parameters
            s_params.update({
                'description': "[%s] Inspection of file: %s" % (s_params['type'], name),
                'generate_alert': generate_alert,
                'max_extracted': config.core.ingester.default_max_extracted,
                'max_supplementary': config.core.ingester.default_max_supplementary,
                'priority': min(s_params.get("priority", 150), config.ui.ingest_max_priority),
                'submitter': user['uname']
            })

            # Calculate file digest and save it to filestore
            digests = identify.get_digests_for_file(out_file)
            sha256 = digests['sha256']

            if not f_transport.exists(sha256):
                f_transport.upload(out_file, sha256, location='far')

            # Setup notification queue if needed
            if notification_queue:
                notification_params = {
                    "queue": notification_queue,
                    "threshold": notification_threshold
                }
            else:
                notification_params = {}

            # Load metadata and setup some default values if they are missing
            ingest_id = baseconv.base62.encode(uuid.uuid4().int)
            metadata = data.get("metadata", {})
            metadata['ingest_id'] = ingest_id
            metadata['type'] = s_params['type']
            if 'ts' not in metadata:
                metadata['ts'] = now_as_iso()

            # Create submission object
            try:
                submission_obj = Submission({
                    "sid": ingest_id,
                    "files": [{'name': name, 'sha256': sha256, 'size': digests['size']}],
                    "notification": notification_params,
                    "metadata": metadata,
                    "params": s_params
                })
            except (ValueError, KeyError) as e:
                return make_api_response("", err=str(e), status_code=400)

            # Send submission object for processing
            ingest.push(submission_obj.as_primitives())
            return make_api_response({"ingest_id": ingest_id})
        finally:
            try:
                # noinspection PyUnboundLocalVariable
                os.unlink(out_file)
            except Exception:
                pass

            try:
                shutil.rmtree(out_dir, ignore_errors=True)
            except Exception:
                pass
