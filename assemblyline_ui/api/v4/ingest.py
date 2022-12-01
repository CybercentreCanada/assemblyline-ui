import json
import os
import shutil
from assemblyline.common.classification import InvalidClassification

from flask import request

from assemblyline.common.codec import decode_file
from assemblyline.common.dict_utils import flatten
from assemblyline.common.isotime import now_as_iso
from assemblyline.common.str_utils import safe_str
from assemblyline.common.uid import get_random_id
from assemblyline.odm.messages.submission import Submission
from assemblyline.odm.models.user import ROLES
from assemblyline.remote.datatypes.queues.named import NamedQueue
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import CLASSIFICATION as Classification, IDENTIFY, TEMP_SUBMIT_DIR, \
    STORAGE, config, FILESTORE
from assemblyline_ui.helper.service import ui_to_submission_params
from assemblyline_ui.helper.submission import download_from_url, ConnectTimeout, FileTooBigException, \
    InvalidUrlException, ForbiddenLocation, submission_received
from assemblyline_ui.helper.user import load_user_settings


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
@api_login(required_priv=['R'], allow_readonly=False, require_role=[ROLES.submission_create])
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
                   port=config.core.redis.persistent.port)

    msg = u.pop(blocking=False)

    return make_api_response(msg)


# noinspection PyUnusedLocal
@ingest_api.route("/get_message_list/<notification_queue>/", methods=["GET"])
@api_login(required_priv=['R'], allow_readonly=False, require_role=[ROLES.submission_create])
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
                   port=config.core.redis.persistent.port)

    while True:
        msg = u.pop(blocking=False)

        if msg is None:
            break

        resp_list.append(msg)

    return make_api_response(resp_list)


# noinspection PyBroadException
@ingest_api.route("/", methods=["POST"])
@api_login(required_priv=['W'], allow_readonly=False, require_role=[ROLES.submission_create])
def ingest_single_file(**kwargs):
    """
    Ingest a single file, sha256 or URL in the system

        Note 1:
            If you are submitting a sha256 or a URL, you must use the application/json encoding and one of
            sha256 or url parameters must be included in the data block.

        Note 2:
            If you are submitting a file directly, you have to use multipart/form-data encoding this
            was done to reduce the memory footprint and speedup file transfers
             ** Read documentation of mime multipart standard if your library does not support it**

            The multipart/form-data for sending binary has two parts:
                - The first part contains a JSON dump of the optional params and uses the name 'json'
                - The last part conatins the file binary, uses the name 'bin' and includes a filename

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
     //REQUIRED VALUES: One of the following
     "sha256": "1234...CDEF"         # SHA256 hash of the file
     "url": "http://...",            # Url to fetch the file from

     //OPTIONAL VALUES
     "name": "file.exe",             # Name of the file

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

    Data Block (Binary):

    --0b34a3c50d3c02dd804a172329a0b2aa               <-- Randomly generated boundary for this http request
    Content-Disposition: form-data; name="json"      <-- JSON data blob part (only previous optional values valid)

    {"params": {"ignore_cache": true}, "generate_alert": true}
    --0b34a3c50d3c02dd804a172329a0b2aa               <-- Switch to next part, file part
    Content-Disposition: form-data; name="bin"; filename="name_of_the_file_to_scan.bin"

    <BINARY DATA OF THE FILE TO SCAN... DOES NOT NEED TO BE ENCODDED>

    --0b34a3c50d3c02dd804a172329a0b2aa--             <-- End of HTTP transmission

    Result example:
    { "ingest_id": <ID OF THE INGESTED FILE> }
    """
    user = kwargs['user']
    out_dir = os.path.join(TEMP_SUBMIT_DIR, get_random_id())
    extracted_path = original_file = None
    try:
        # Get data block and binary blob
        if 'multipart/form-data' in request.content_type:
            if 'json' in request.values:
                data = json.loads(request.values['json'])
            else:
                data = {}
            binary = request.files['bin']
            name = data.get("name", binary.filename)
            sha256 = None
            url = None
            default_description = f"Inspection of file: {name}"
        elif 'application/json' in request.content_type:
            data = request.json
            binary = None
            sha256 = data.get('sha256', None)
            url = data.get('url', None)
            name = data.get("name", None) or sha256 or os.path.basename(url) or None
            default_description = f"Inspection of {name}"
            if sha256:
                default_description = f"Inspection of file: {sha256}"
            elif url:
                default_description = f"Inspection of URL: {url}"

        else:
            return make_api_response({}, "Invalid content type", 400)

        if not data:
            return make_api_response({}, "Missing data block", 400)

        # Get notification queue parameters
        notification_queue = data.get('notification_queue', None)
        notification_threshold = data.get('notification_threshold', None)
        if not isinstance(notification_threshold, int) and notification_threshold:
            return make_api_response({}, "notification_threshold should be and int", 400)

        # Get file name
        if not name:
            return make_api_response({}, "Filename missing", 400)

        name = safe_str(os.path.basename(name))
        if not name:
            return make_api_response({}, "Invalid filename", 400)

        try:
            os.makedirs(out_dir)
        except Exception:
            pass
        original_file = out_file = os.path.join(out_dir, get_random_id())

        # Prepare variables
        extra_meta = {}
        fileinfo = None
        do_upload = True
        al_meta = {}

        # Load default user params
        s_params = ui_to_submission_params(load_user_settings(user))

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

        # Check if external submit is allowed
        default_external_sources = s_params.pop('default_external_sources', [])

        # Load file
        if not binary:
            if sha256:
                fileinfo = STORAGE.file.get_if_exists(sha256, as_obj=False,
                                                      archive_access=config.datastore.ilm.update_archive)
                if FILESTORE.exists(sha256):
                    if fileinfo:
                        if not Classification.is_accessible(user['classification'], fileinfo['classification']):
                            return make_api_response({}, "SHA256 does not exist in Assemblyline", 404)
                        else:
                            # File's classification must be applied at a minimum
                            s_params['classification'] = Classification.max_classification(s_params['classification'],
                                                                                           fileinfo['classification'])
                    else:
                        # File is in storage and the DB no need to upload anymore
                        do_upload = False
                    # File exists in the filestore and the user has appropriate file access
                    FILESTORE.download(sha256, out_file)
                elif default_external_sources:
                    dl_from = None
                    available_sources = [x for x in config.submission.sha256_sources
                                         if Classification.is_accessible(user['classification'],
                                                                         x.classification) and
                                         x.name in default_external_sources]
                    try:
                        for source in available_sources:
                            src_url = source.url.replace(source.replace_pattern, sha256)
                            src_data = source.data.replace(source.replace_pattern, sha256) if source.data else None
                            failure_pattern = source.failure_pattern.encode('utf-8') if source.failure_pattern else None
                            dl_from = download_from_url(src_url, out_file, data=src_data, method=source.method,
                                                        headers=source.headers, proxies=source.proxies,
                                                        verify=source.verify, validate=False,
                                                        failure_pattern=failure_pattern)
                            if dl_from:
                                # Apply minimum classification for the source
                                s_params['classification'] = \
                                    Classification.max_classification(s_params['classification'],
                                                                      source.classification)
                                extra_meta['original_source'] = source.name
                                break
                    except FileTooBigException:
                        return make_api_response({}, "File too big to be scanned.", 400)

                    if not dl_from:
                        return make_api_response(
                            {},
                            "SHA256 does not exist in Assemblyline or any of the selected sources", 404)
                else:
                    return make_api_response({}, "SHA256 does not exist in Assemblyline", 404)
            elif url:
                if not config.ui.allow_url_submissions:
                    return make_api_response({}, "URL submissions are disabled in this system", 400)

                try:
                    if not download_from_url(url, out_file, headers=config.ui.url_submission_headers,
                                             proxies=config.ui.url_submission_proxies,
                                             timeout=config.ui.url_submission_timeout):

                        return make_api_response({}, "Submitted URL cannot be found.", 400)

                    extra_meta['submitted_url'] = url
                except FileTooBigException:
                    return make_api_response({}, "File too big to be scanned.", 400)
                except InvalidUrlException:
                    return make_api_response({}, "Url provided is invalid.", 400)
                except ForbiddenLocation:
                    return make_api_response({}, "Hostname in this URL cannot be resolved.", 400)
                except ConnectTimeout:
                    return make_api_response({}, 'Connection timeout has occurred while fetching data.', 400)
            else:
                return make_api_response({}, "Missing file to scan. No binary, sha256 or url provided.", 400)
        else:
            binary.save(out_file)

        if do_upload and os.path.getsize(out_file) == 0:
            return make_api_response({}, err="File empty. Ingestion failed", status_code=400)

        # Apply group params if not specified
        if 'groups' not in s_params:
            s_params['groups'] = user['groups']

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
        metadata = flatten(data.get("metadata", {}))
        metadata['ingest_id'] = ingest_id
        metadata['type'] = s_params['type']
        metadata.update(al_meta)
        if 'ts' not in metadata:
            metadata['ts'] = now_as_iso()
        metadata.update(extra_meta)

        # Set description if it does not exists
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

        return make_api_response({"ingest_id": ingest_id})

    finally:
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
