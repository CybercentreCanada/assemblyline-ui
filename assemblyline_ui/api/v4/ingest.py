import os
import shutil

from assemblyline_core.ingester.constants import INGEST_QUEUE_NAME
from flask import request

from assemblyline.common.isotime import now_as_iso
from assemblyline.common.uid import get_random_id
from assemblyline.odm.messages.submission import Submission
from assemblyline.odm.models.user import ROLES
from assemblyline.remote.datatypes.queues.named import NamedQueue
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import (
    ARCHIVESTORE,
    FILESTORE,
    LOGGER,
    STORAGE,
    config,
)
from assemblyline_ui.helper.submission import (
    FileTooBigException,
    init_submission,
    submission_received,
)
from assemblyline_ui.helper.user import (
    check_async_submission_quota,
    decrement_submission_ingest_quota,
)

SUB_API = 'ingest'
ingest_api = make_subapi_blueprint(SUB_API, api_version=4)
ingest_api._doc = "Ingest files for large volume processing"

ingest = NamedQueue(
    INGEST_QUEUE_NAME,
    host=config.core.redis.persistent.host,
    port=config.core.redis.persistent.port)
MAX_SIZE = config.submission.max_file_size

DEFAULT_INGEST_PARAMS = {
    'deep_scan': False,
    "priority": 150,
    "ignore_cache": False,
    "ignore_recursion_prevention": False,
    "ignore_filtering": False,
    "type": "INGEST"
}

# noinspection PyUnusedLocal
@ingest_api.route("/get_message/<notification_queue>/", methods=["GET"])
@api_login(allow_readonly=False, require_role=[ROLES.submission_create])
def get_message(notification_queue, **kwargs):
    """
    Get one message on the specified notification queue

    Variables:
    notification_queue       => Queue to get the message from

    Arguments:
    None

    Data Block:
    None

    Result example:
    {}          # A message
    """
    u = NamedQueue("nq-%s" % notification_queue,
                   host=config.core.redis.persistent.host,
                   port=config.core.redis.persistent.port)

    msg = u.pop(blocking=False)

    return make_api_response(msg)


# noinspection PyUnusedLocal
@ingest_api.route("/get_message_list/<notification_queue>/", methods=["GET"])
@api_login(allow_readonly=False, require_role=[ROLES.submission_create])
def get_all_messages(notification_queue, **kwargs):
    """
    Get all messages on the specified notification queue

    Variables:
    notification_queue       => Queue to get the message from

    Arguments:
    page_size                => Number of messages to get back from queue

    Data Block:
    None

    Result example:
    []            # List of messages
    """
    resp_list = []

    # Default page_size will return all the messages within the queue
    page_size = int(request.args.get("page_size", -1))

    u = NamedQueue("nq-%s" % notification_queue,
                   host=config.core.redis.persistent.host,
                   port=config.core.redis.persistent.port)

    while True and len(resp_list) != page_size:
        msg = u.pop(blocking=False)

        if msg is None:
            break

        resp_list.append(msg)

    return make_api_response(resp_list)


# noinspection PyBroadException
@ingest_api.route("/", methods=["POST"])
@api_login(allow_readonly=False, require_role=[ROLES.submission_create], count_toward_quota=False)
def ingest_single_file(**kwargs):
    """
    Ingest a single file, sha256 or URL in the system

        Note 1:
            If you are submitting a sha256 or a URL, you must use the application/json encoding and one of
            sha256 or url parameters must be included in the data block.

        Note 2:
            If you are submitting a file directly, you should use multipart/form-data encoding as this
            was done to reduce the memory footprint and speedup file transfers.
             ** Read documentation of mime multipart standard if your library does not support it**

            The multipart/form-data for sending binary has two parts:
                - The first part contains a JSON dump of the optional params and uses the name 'json'
                - The last part contains the file binary, uses the name 'bin' and includes a filename

            If your system can handle the memory footprint and slowdown, you can also submit a file
            via the plaintext (not encoded) or base64 (encoded) parameters included in the data block.

        Note 3:
            The ingest API uses the user's default settings to submit files to the system
            unless these settings are overridden in the 'params' field. Although, there are
            exceptions to that rule. Fields deep_scan, ignore_filtering, ignore_cache are
            resetted to False because the lead to dangerous behavior in the system.

    Variables:
    None

    Arguments:
    None

    Data Block (SHA256 or URL):
    {
      // REQUIRED: One of the two following
      "sha256": "123...DEF",      # SHA256 hash of the file already in the datastore
      "url": "http://...",        # Url to fetch the file from

      // NOT RECOMMENDED: Or one of the two following
      "plaintext": "<RAW DATA OF THE FILE TO SCAN... ENCODED AS UTF-8 STRING>",
      "base64": "<BINARY DATA OF THE FILE TO SCAN... ENCODED AS BASE64 STRING>",

      // CONDITIONALLY OPTIONAL VALUES:
      "submission_profile": "static",       # Name of submission profile to use (condition: user has "submission_customize" role)

      // OPTIONAL VALUES
      "name": "file.exe",                   # Name of the file to scan otherwise the sha256 or base file of the url

      "metadata": {                         # Submission metadata
        "key": val,                             # Key/Value pair for metadata parameters
      },

      "params": {                           # Submission parameters
        "key": val,                             # Key/Value pair for params that differ from the user's defaults
      },                                        # Default params can be fetch at /api/v3/user/submission_params/<user>/

      "generate_alert": False,        # Generate an alert in our alerting system or not
      "notification_queue": None,     # Name of the notification queue
      "notification_threshold": None, # Threshold for notification
    }

    Data Block (Binary):

    --0b34a3c50d3c02dd804a172329a0b2aa               <-- Randomly generated boundary for this http request
    Content-Disposition: form-data; name="json"      <-- JSON data blob part (only previous optional values valid)

    {"params": {"ignore_cache": true}, "generate_alert": true}
    --0b34a3c50d3c02dd804a172329a0b2aa               <-- Switch to next part, file part
    Content-Disposition: form-data; name="bin"; filename="name_of_the_file_to_scan.bin"

    <BINARY DATA OF THE FILE TO SCAN... DOES NOT NEED TO BE ENCODED>

    --0b34a3c50d3c02dd804a172329a0b2aa--             <-- End of HTTP transmission

    Result example:
    { "ingest_id": <ID OF THE INGESTED FILE> }
    """
    success = False
    user = kwargs['user']

    # Check daily submission quota
    quota_error = check_async_submission_quota(user)
    if quota_error:
        return make_api_response("", quota_error, 503)

    try:
        try:
            # Initialize submission validation process
            data, out_file, name, fileinfo, s_params, metadata = init_submission(request, user, endpoint="ingest")
        except FileTooBigException as e:
            LOGGER.warning(f"[{user['uname']}] {e}")
            return make_api_response({}, str(e), 413)
        except FileNotFoundError as e:
            return make_api_response({}, str(e), 404)
        except (PermissionError, Exception) as e:
            return make_api_response({}, str(e), 400)


        # Get notification queue parameters
        notification_queue = data.get('notification_queue', None)
        notification_threshold = data.get('notification_threshold', None)
        if not isinstance(notification_threshold, int) and notification_threshold:
            return make_api_response({}, "notification_threshold should be and int", 400)

        # Set any dangerous user settings to safe values (if wasn't set in request)
        for k, v in DEFAULT_INGEST_PARAMS.items():
            s_params.setdefault(k, v)


        # Determine where the file exists and whether or not we need to re-upload to hot storage
        if not STORAGE.file.exists(fileinfo['sha256']):
            # File was downloaded from an external source but wasn't known to the system
            do_upload = True
        elif fileinfo and FILESTORE.exists(fileinfo['sha256']):
            # File is in storage and the DB no need to upload anymore
            do_upload = False
        elif FILESTORE != ARCHIVESTORE and ARCHIVESTORE.exists(fileinfo['sha256']):
            # File is only in archivestorage so I'll still need to upload it to the hot storage
            do_upload = True
        else:
            # Corner case: If we do know about the file but it doesn't exist in our filestores
            do_upload = True

        # Override final parameters
        s_params.update({
            'generate_alert': s_params.get('generate_alert', False),
            'max_extracted': config.core.ingester.default_max_extracted,
            'max_supplementary': config.core.ingester.default_max_supplementary,
            'priority': min(s_params.get("priority", 150), config.ui.ingest_max_priority),
        })

        # Freshen file object
        expiry = now_as_iso(s_params['ttl'] * 24 * 60 * 60) if s_params.get('ttl', None) else None
        STORAGE.save_or_freshen_file(fileinfo['sha256'], fileinfo, expiry, s_params['classification'])

        # Save the file to the filestore if needs be
        # also no need to test if exist before upload because it already does that
        if do_upload:
            FILESTORE.upload(out_file, fileinfo['sha256'], location='far')

        # Setup notification queue if needed
        if notification_queue:
            notification_params = {
                "queue": notification_queue,
                "threshold": notification_threshold
            }
        else:
            notification_params = {}

        # Load metadata, setup some default values if they are missing and append the cart metadata
        ingest_id = get_random_id()
        metadata['ingest_id'] = ingest_id
        metadata['type'] = s_params['type']
        if 'ts' not in metadata:
            metadata['ts'] = now_as_iso()

        # Create submission object
        try:
            submission_obj = Submission({
                "sid": ingest_id,
                "files": [{'name': name, 'sha256': fileinfo['sha256'], 'size': fileinfo['size']}],
                "notification": notification_params,
                "metadata": metadata,
                "params": s_params
            })
        except (ValueError, KeyError) as e:
            return make_api_response({}, err=str(e), status_code=400)

        # Send submission object for processing
        ingest.push(submission_obj.as_primitives())
        submission_received(submission_obj)

        success = True
        return make_api_response({"ingest_id": ingest_id})

    finally:
        if not success:
            # We had an error during the submission, release the quotas for the user
            decrement_submission_ingest_quota(user)

        # Cleanup files on disk
        try:
            # noinspection PyUnboundLocalVariable
            os.unlink(out_file)
        except Exception:
            pass

        try:
            shutil.rmtree(os.path.dirname(out_file), ignore_errors=True)
        except Exception:
            pass
