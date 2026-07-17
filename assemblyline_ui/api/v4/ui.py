#####################################
# UI ONLY APIs

import os
import tempfile

from assemblyline.common import forge
from assemblyline.common.bundling import import_bundle
from assemblyline.odm.messages.submission import Submission
from assemblyline.odm.models.user import ROLES
from assemblyline_core.submission_client import SubmissionClient
from cart import get_metadata_only, is_cart
from flask import request

from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import (
    FILESTORE,
    IDENTIFY,
    STORAGE,
    TEMP_DIR,
    config,
)
from assemblyline_ui.helper.submission import (
    init_submission,
    submission_received,
)
from assemblyline_ui.helper.user import (
    check_submission_quota,
    decrement_submission_quota,
)

SUB_API = 'ui'
ui_api = make_subapi_blueprint(SUB_API, api_version=4)
ui_api._doc = "UI specific operations"


#############################
# Files Functions

def get_cache_name(identifier, chunk_number=None):
    if chunk_number is None:
        return identifier[:36].replace('-', '_')
    return f"{identifier[:36].replace('-', '_')}_part{chunk_number}"


##############################
# APIs

# noinspection PyUnusedLocal
@ui_api.route("/flowjs/", methods=["GET"])
@api_login(audit=False, check_xsrf_token=False, allow_readonly=False, require_role=[ROLES.submission_create],
           count_toward_quota=False)
def flowjs_check_chunk(**kwargs):
    """
    Flowjs check file chunk.

    This API is reserved for the FLOWJS file uploader. It allows FLOWJS
    to check if the file chunk already exists on the server.

    Variables:
    None

    Arguments (REQUIRED):
    flowChunkNumber      => Current chunk number
    flowIdentifier       => File unique identifier

    Data Block:
    None

    Result example:
    {'exists': True}     #Does the chunk exists on the server?
    """

    try:
        flow_chunk_number = request.args["flowChunkNumber"]
        flow_identifier = request.args["flowIdentifier"]
    except KeyError as e:
        return make_api_response("", f"Required argument missing: {e}", 412)

    filename = get_cache_name(flow_identifier, flow_chunk_number)
    with forge.get_cachestore("flowjs", config) as cache:
        if cache.exists(filename):
            return make_api_response({"exist": True})
        else:
            return make_api_response({"exist": False, "msg": "Chunk does not exist, please send it!"}, status_code=204)


# noinspection PyBroadException, PyUnusedLocal
@ui_api.route("/flowjs/", methods=["POST"])
@api_login(audit=False, check_xsrf_token=False, allow_readonly=False, require_role=[ROLES.submission_create],
           count_toward_quota=False)
def flowjs_upload_chunk(**kwargs):
    """
    Flowjs upload file chunk.

    This API is reserved for the FLOWJS file uploader. It allows
    FLOWJS to upload a file chunk to the server.

    Variables:
    None

    Data Block (REQUIRED):

    --0b34a3c50d3c02dd804a172329a0b2aa                          <-- Randomly generated boundary for this http request
    Content-Disposition: form-data; name="flowChunkNumber"      <-- Current chunk number

    1
    --0b34a3c50d3c02dd804a172329a0b2aa                          <-- Switch to next part, file part
    Content-Disposition: form-data; name="flowIdentifier"       <-- File unique identifier

    00000000-0000-0000-0000-000000000000_000000000_testfile.txt
    --0b34a3c50d3c02dd804a172329a0b2aa                          <-- Switch to next part, file part
    Content-Disposition: form-data; name="flowTotalChunks"      <-- Total number of chunks

    10
    --0b34a3c50d3c02dd804a172329a0b2aa
    Content-Disposition: form-data; name="file"; filename="testfile.txt" <-- File part
    Content-Type: application/octet-stream

    <BINARY DATA OF THE FILE TO UPLOAD... DOES NOT NEED TO BE ENCODED>
    --0b34a3c50d3c02dd804a172329a0b2aa--                        <-- End of HTTP transmission

    Result example:
    {
     'success': True,     #Did the upload succeeded?
     'completed': False   #Are all chunks received by the server?
     }
    """

    try:
        flow_chunk_number = int(request.form["flowChunkNumber"])
        flow_identifier = request.form["flowIdentifier"]
        flow_total_chunks = int(request.form["flowTotalChunks"])
    except KeyError as e:
        return make_api_response("", f"Required argument missing: {e}", 412)
    except ValueError as e:
        return make_api_response("", f"Invalid argument type: {e}", 412)

    # Evaluate if the chunk number is valid, if not return an error
    if flow_chunk_number == 0 or flow_chunk_number > flow_total_chunks:
        return make_api_response("", "Invalid chunk number", 412)

    with forge.get_cachestore("flowjs", config) as cache:
        # Write the chunk to the cache
        file_obj = request.files['file']
        chunk_name = get_cache_name(flow_identifier, flow_chunk_number)
        cache.save(chunk_name, file_obj.stream.read())

        # Check if all chunks have been received, assume complete until proven otherwise
        completed = True

        # Test in reverse order to fail fast
        for chunk in range(int(flow_total_chunks), 0, -1):
            chunk_name = get_cache_name(flow_identifier, chunk)
            if not cache.exists(chunk_name):
                completed = False
                break

        if completed:
            # Attempt file reconstruction and save to cache with the original identifier
            ui_sid = get_cache_name(flow_identifier)
            with tempfile.NamedTemporaryFile(dir=TEMP_DIR) as target_file:
                # Iterate through the chunks in order to reconstruct the file
                for chunk in range(int(flow_total_chunks)):
                    chunk_name = get_cache_name(flow_identifier, chunk+1)
                    # Write chunks to temporary file
                    target_file.write(cache.get(chunk_name))
                    # Delete the chunk from the cache
                    cache.delete(chunk_name)

                # Once the file is reconstructed, save it to the cache with the original identifier
                target_file.flush()
                target_file.seek(0)
                cache.save(ui_sid, target_file.read())

    return make_api_response({'success': True, 'completed': completed})


# noinspection PyBroadException
@ui_api.route("/start/<ui_sid>/", methods=["POST"])
@api_login(audit=False, allow_readonly=False, require_role=[ROLES.submission_create], count_toward_quota=False)
def start_ui_submission(ui_sid, **kwargs):
    """
    Start UI submission.

    Starts processing after files where uploaded to the server.

    Variables:
    ui_sid     => UUID for the current UI file upload

    Arguments:
    None

    Data Block (REQUIRED):
    Dictionary of UI specific user settings

    Result example:
    {
     'started': True,                    # Has the submission started processing?
     'sid' : "c7668cfa-...-c4132285142e" # Submission ID
    }
    """
    user = kwargs['user']

    # Check if we've reached the quotas
    quota_error = check_submission_quota(user)
    if quota_error:
        return make_api_response("", quota_error, 503)

    ui_params = request.json
    submit_result = None
    submitted_file = None

    # Download the file from the cache

    with forge.get_cachestore("flowjs", config) as cache:
        ui_sid = get_cache_name(ui_sid)
        fname = ui_params.pop('filename', ui_sid)
        if not cache.exists(ui_sid):
            # No file was found for the given ID, return an error and decrement the submission quota for the user
            decrement_submission_quota(user)
            return make_api_response({"started": False, "sid": None}, "No files where found for ID %s. "
                                                                        "Try again..." % ui_sid, 404)
        # Submit to dispatcher
        try:
            # Save uploaded file to a temporary file for processing
            submitted_file = tempfile.NamedTemporaryFile(dir=TEMP_DIR).name
            cache.download(ui_sid, submitted_file)

            # Check if the file is a CART bundle
            with open(submitted_file, "rb") as temp_file:
                if is_cart(temp_file.read(256)):
                    meta = get_metadata_only(submitted_file)
                    if meta.get('al', {}).get('type', 'unknown') == 'archive/bundle/al':
                        # Import the submission bundle and return the submission ID
                        submission = import_bundle(submitted_file, allow_incomplete=True, identify=IDENTIFY,
                                                   dtl=ui_params.get('ui_params', {}).get('ttl'))
                        return make_api_response({"started": True, "sid": submission['sid']})

            # Initialize submission validation process
            _, _, _, _, s_params, metadata = init_submission(request, user, endpoint="ui")
            s_params['quota_item'] = True
            allow_description_overwrite = False
            if not s_params.get("description"):
                # If no custom description is specified, create one based on filename
                s_params["description"] = f"Inspection of file: {fname}"
                allow_description_overwrite = True
            submission_obj = Submission({
                "files": [],
                "metadata": metadata,
                "params": s_params
            })

            # Attempt to submit the file to the dispatcher
            submit_result = SubmissionClient(
                datastore=STORAGE, filestore=FILESTORE, config=config, identify=IDENTIFY
            ).submit(
                submission_obj,
                local_files=[(fname, submitted_file)],
                allow_description_overwrite=allow_description_overwrite
            )
            submission_received(submission_obj)
            return make_api_response({"started": True, "sid": submit_result.sid})
        except Exception as e:
            # If an error occurs during submission, return an error response
            return make_api_response("", err=str(e), status_code=400)
        finally:
            # Perform cleanup actions regardless of whether submission was successful or not
            if submit_result is None:
                # We had an error during the submission, release the quotas for the user
                decrement_submission_quota(user)

            if submitted_file and os.path.exists(submitted_file):
                # Clean up the temporary file
                os.remove(submitted_file)
