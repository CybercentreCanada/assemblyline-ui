import base64
import hashlib
import io
import json
import os
import shutil

from flask import request

from assemblyline.common.classification import InvalidClassification
from assemblyline.common.codec import decode_file
from assemblyline.common.dict_utils import flatten
from assemblyline.common.isotime import now_as_iso
from assemblyline.common.str_utils import safe_str
from assemblyline.common.uid import get_random_id
from assemblyline.odm.messages.submission import Submission
from assemblyline.odm.models.user import ROLES
from assemblyline.remote.datatypes.queues.named import NamedQueue
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import ARCHIVESTORE, CLASSIFICATION as Classification, IDENTIFY, TEMP_SUBMIT_DIR, \
    STORAGE, config, FILESTORE, metadata_validator
from assemblyline_ui.helper.service import ui_to_submission_params
from assemblyline_ui.helper.submission import FileTooBigException, submission_received, refang_url, fetch_file, \
    FETCH_METHODS
from assemblyline_ui.helper.user import check_async_submission_quota, decrement_submission_ingest_quota, \
    load_user_settings


SUB_API = 'ingest'
ingest_api = make_subapi_blueprint(SUB_API, api_version=4)
ingest_api._doc = "Ingest files for large volume processing"

ingest = NamedQueue(
    "m-ingest",
    host=config.core.redis.persistent.host,
    port=config.core.redis.persistent.port)
MAX_SIZE = config.submission.max_file_size


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
                - The last part conatins the file binary, uses the name 'bin' and includes a filename

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

      // OPTIONAL VALUES
      "name": "file.exe",         # Name of the file to scan otherwise the sha256 or base file of the url

      "metadata": {               # Submission metadata
        "key": val,                 # Key/Value pair for metadata parameters
      },

      "params": {                 # Submission parameters
        "key": val,                 # Key/Value pair for params that differ from the user's defaults
      },                            # Default params can be fetch at /api/v3/user/submission_params/<user>/

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
        out_dir = os.path.join(TEMP_SUBMIT_DIR, get_random_id())
        extracted_path = original_file = None
        string_type = None
        string_value = None

        # Get data block and binary blob
        if 'multipart/form-data' in request.content_type:
            if 'json' in request.values:
                data = json.loads(request.values['json'])
            else:
                data = {}
            binary = request.files['bin']
            name = safe_str(os.path.basename(data.get("name", binary.filename) or ""))
        elif 'application/json' in request.content_type:
            data = request.json
            binary = data.get('plaintext', '').encode() or base64.b64decode(data.get('base64', ''))

            # Determine if we're expected to fetch a file
            for method in FETCH_METHODS:
                if data.get(method):
                    string_type, string_value = method, data[method]
                    break

            hash = string_value
            if string_type == "url":
                string_value = refang_url(string_value)
                name = string_value
            else:
                hash = string_value
                if binary:
                    hash = safe_str(hashlib.sha256(binary).hexdigest())
                    binary = io.BytesIO(binary)
                name = safe_str(os.path.basename(data.get("name", None) or hash or ""))
        else:
            return make_api_response({}, "Invalid content type", 400)

        # Get default description
        default_description = f"Inspection of {'URL' if string_type == 'url' else 'file'}: {name}"

        # Get file name
        if not name:
            return make_api_response({}, "Filename missing", 400)

        # Get notification queue parameters
        notification_queue = data.get('notification_queue', None)
        notification_threshold = data.get('notification_threshold', None)
        if not isinstance(notification_threshold, int) and notification_threshold:
            return make_api_response({}, "notification_threshold should be and int", 400)

        try:
            os.makedirs(out_dir)
        except Exception:
            pass
        original_file = out_file = os.path.join(out_dir, get_random_id())

        # Prepare variables
        do_upload = True
        al_meta = {}

        user_settings = load_user_settings(user)

        # Grab the user's `default_external_sources` from their settings as the default
        default_external_sources = user_settings.pop('default_external_sources', [])

        # Load default user params from user settings
        s_params = ui_to_submission_params(user_settings)

        # Reset dangerous user settings to safe values
        s_params.update({
            'deep_scan': False,
            "priority": 150,
            "ignore_cache": False,
            # the following one line can be removed after assemblyline 4.6+
            "ignore_dynamic_recursion_prevention": False,
            "ignore_recursion_prevention": False,
            "ignore_filtering": False,
            "type": "INGEST"
        })

        # Apply provided params
        s_params.update(data.get("params", {}))

        # Use the `default_external_sources` if specified as a param in request otherwise default to user's settings
        default_external_sources = s_params.pop('default_external_sources', []) or default_external_sources

        metadata = flatten(data.get("metadata", {}))
        found = False
        fileinfo = None
        # Load file
        if not binary:
            if string_type:
                try:
                    found, fileinfo = fetch_file(string_type, string_value, user, s_params, metadata, out_file,
                                                 default_external_sources)
                    if not found:
                        raise FileNotFoundError(
                            f"{string_type.upper()} does not exist in Assemblyline or any of the selected sources")
                except FileTooBigException:
                    return make_api_response({}, "File too big to be scanned.", 400)
                except FileNotFoundError as e:
                    return make_api_response({}, str(e), 404)
                except PermissionError as e:
                    return make_api_response({}, str(e), 400)
            else:
                return make_api_response({}, "Missing file to scan. No binary or fetching method provided.", 400)
        else:
            with open(out_file, "wb") as my_file:
                shutil.copyfileobj(binary, my_file, 16384)

        # Determine where the file exists and whether or not we need to re-upload to hot storage
        if found and string_type != "url":
            if not fileinfo:
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

        if do_upload and os.path.getsize(out_file) == 0:
            return make_api_response({}, err="File empty. Ingestion failed", status_code=400)

        # Apply group params if not specified
        if 'groups' not in s_params:
            s_params['groups'] = [g for g in user['groups'] if g in s_params['classification']]

        # Get generate alert parameter
        generate_alert = data.get('generate_alert', s_params.get('generate_alert', False))
        if not isinstance(generate_alert, bool):
            return make_api_response({}, "generate_alert should be a boolean", 400)

        # Override final parameters
        s_params.update({
            'generate_alert': generate_alert,
            'max_extracted': config.core.ingester.default_max_extracted,
            'max_supplementary': config.core.ingester.default_max_supplementary,
            'priority': min(s_params.get("priority", 150), config.ui.ingest_max_priority),
            'submitter': user['uname']
        })

        # Enforce maximum DTL
        if config.submission.max_dtl > 0:
            s_params['ttl'] = min(
                int(s_params['ttl']),
                config.submission.max_dtl) if int(s_params['ttl']) else config.submission.max_dtl

        # No need to re-calculate fileinfo if we have it already
        if not fileinfo:
            # Calculate file digest
            fileinfo = IDENTIFY.fileinfo(out_file)

            # Validate file size
            if fileinfo['size'] > MAX_SIZE and not s_params.get('ignore_size', False):
                msg = f"File too large ({fileinfo['size']} > {MAX_SIZE}). Ingestion failed"
                return make_api_response({}, err=msg, status_code=413)
            elif fileinfo['size'] == 0:
                return make_api_response({}, err="File empty. Ingestion failed", status_code=400)

            # Decode cart if needed
            extracted_path, fileinfo, al_meta = decode_file(out_file, fileinfo, IDENTIFY)
            if extracted_path:
                out_file = extracted_path

        if fileinfo["type"].startswith("uri/") and "uri_info" in fileinfo and "uri" in fileinfo["uri_info"]:
            al_meta["name"] = fileinfo["uri_info"]["uri"]

        # Alter filename and classification based on CaRT output
        meta_classification = al_meta.pop('classification', s_params['classification'])
        if meta_classification != s_params['classification']:
            try:
                s_params['classification'] = Classification.max_classification(meta_classification,
                                                                               s_params['classification'])
            except InvalidClassification as ic:
                return make_api_response({}, "The classification found inside the cart file cannot be merged with "
                                             f"the classification the file was submitted as: {str(ic)}", 400)
        name = al_meta.pop('name', name)

        # Validate ingest classification
        if not Classification.is_accessible(user['classification'], s_params['classification']):
            return make_api_response({}, "You cannot start a submission with higher "
                                     "classification then you're allowed to see", 400)

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
        metadata.update(al_meta)
        if 'ts' not in metadata:
            metadata['ts'] = now_as_iso()

        # Validate the metadata (use validation scheme if we have one configured for the ingest_type)
        validation_scheme = config.submission.metadata.ingest.get('_default', {})
        validation_scheme.update(config.submission.metadata.ingest.get(s_params['type'], {}))
        metadata_error = metadata_validator.check_metadata(metadata, validation_scheme=validation_scheme)
        if metadata_error:
            return make_api_response({}, err=metadata_error[1], status_code=400)

        if s_params.get('auto_archive', False):
            # If the submission was set to auto-archive we need to validate the archive metadata fields also
            metadata_error = metadata_validator.check_metadata(
                metadata, validation_scheme=config.submission.metadata.archive, skip_elastic_fields=True)
            if metadata_error:
                return make_api_response({}, err=metadata_error[1], status_code=400)

        # Set description if it does not exists
        if fileinfo["type"].startswith("uri/") and "uri_info" in fileinfo and "uri" in fileinfo["uri_info"]:
            default_description = f"Inspection of URL: {fileinfo['uri_info']['uri']}"
        s_params['description'] = s_params['description'] or f"[{s_params['type']}] {default_description}"

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
            if original_file and os.path.exists(original_file):
                os.unlink(original_file)
        except Exception:
            pass

        try:
            if extracted_path and os.path.exists(extracted_path):
                os.unlink(extracted_path)
        except Exception:
            pass

        try:
            if os.path.exists(out_dir):
                shutil.rmtree(out_dir, ignore_errors=True)
        except Exception:
            pass
