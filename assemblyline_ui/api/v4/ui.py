#####################################
# UI ONLY APIs

import os

from cart import is_cart, get_metadata_only
from flask import request

from assemblyline.common import forge
from assemblyline.common.bundling import import_bundle
from assemblyline.common.str_utils import safe_str
from assemblyline.odm.messages.submission import Submission
from assemblyline.odm.models.user import ROLES
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import TEMP_DIR, STORAGE, FILESTORE, config, CLASSIFICATION as Classification, \
    IDENTIFY
from assemblyline_ui.helper.service import ui_to_submission_params
from assemblyline_ui.helper.submission import submission_received
from assemblyline_ui.helper.user import check_submission_quota, decrement_submission_quota
from assemblyline_core.submission_client import SubmissionClient, SubmissionException

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
@api_login(audit=False, check_xsrf_token=False, allow_readonly=False, require_role=[ROLES.submission_create])
def flowjs_check_chunk(**kwargs):
    """
    Flowjs check file chunk.

    This API is reserved for the FLOWJS file uploader. It allows FLOWJS
    to check if the file chunk already exists on the server.

    Variables:
    None

    Arguments (REQUIRED):
    flowChunkNumber      => Current chunk number
    flowFilename         => Original filename
    flowTotalChunks      => Total number of chunks
    flowIdentifier       => File unique identifier
    flowCurrentChunkSize => Size of the current chunk

    Data Block:
    None

    Result example:
    {'exists': True}     #Does the chunk exists on the server?
    """

    flow_chunk_number = request.args.get("flowChunkNumber", None)
    flow_chunk_size = request.args.get("flowChunkSize", None)
    flow_total_size = request.args.get("flowTotalSize", None)
    flow_filename = request.args.get("flowFilename", None)
    flow_total_chunks = request.args.get("flowTotalChunks", None)
    flow_identifier = request.args.get("flowIdentifier", None)
    flow_current_chunk_size = request.args.get("flowCurrentChunkSize", None)

    if not flow_chunk_number or not flow_identifier or not flow_current_chunk_size or not flow_filename \
            or not flow_total_chunks or not flow_chunk_size or not flow_total_size:
        return make_api_response("", "Required arguments missing. flowChunkNumber, flowIdentifier, "
                                     "flowCurrentChunkSize, flowChunkSize and flowTotalSize "
                                     "should always be present.", 412)

    filename = get_cache_name(flow_identifier, flow_chunk_number)
    with forge.get_cachestore("flowjs", config) as cache:
        if cache.exists(filename):
            return make_api_response({"exist": True})
        else:
            return make_api_response({"exist": False, "msg": "Chunk does not exist, please send it!"}, status_code=204)


# noinspection PyBroadException, PyUnusedLocal
@ui_api.route("/flowjs/", methods=["POST"])
@api_login(audit=False, check_xsrf_token=False, allow_readonly=False, require_role=[ROLES.submission_create])
def flowjs_upload_chunk(**kwargs):
    """
    Flowjs upload file chunk.

    This API is reserved for the FLOWJS file uploader. It allows
    FLOWJS to upload a file chunk to the server.

    Variables:
    None

    Arguments (REQUIRED):
    flowChunkNumber      => Current chunk number
    flowChunkSize        => Usual size of the chunks
    flowCurrentChunkSize => Size of the current chunk
    flowTotalSize        => Total size for the file
    flowIdentifier       => File unique identifier
    flowFilename         => Original filename
    flowRelativePath     => Relative path of the file on the client
    flowTotalChunks      => Total number of chunks

    Data Block:
    None

    Result example:
    {
     'success': True,     #Did the upload succeeded?
     'completed': False   #Are all chunks received by the server?
     }
    """

    flow_chunk_number = request.form.get("flowChunkNumber", None)
    flow_chunk_size = request.form.get("flowChunkSize", None)
    flow_current_chunk_size = request.form.get("flowCurrentChunkSize", None)
    flow_total_size = request.form.get("flowTotalSize", None)
    flow_identifier = request.form.get("flowIdentifier", None)
    flow_filename = safe_str(request.form.get("flowFilename", None))
    flow_relative_path = request.form.get("flowRelativePath", None)
    flow_total_chunks = request.form.get("flowTotalChunks", None)
    completed = True

    if not flow_chunk_number or not flow_chunk_size or not flow_current_chunk_size or not flow_total_size \
            or not flow_identifier or not flow_filename or not flow_relative_path or not flow_total_chunks:
        return make_api_response("", "Required arguments missing. flowChunkNumber, flowChunkSize, "
                                     "flowCurrentChunkSize, flowTotalSize, flowIdentifier, flowFilename, "
                                     "flowRelativePath and flowTotalChunks should always be present.", 412)

    filename = get_cache_name(flow_identifier, flow_chunk_number)

    with forge.get_cachestore("flowjs", config) as cache:
        file_obj = request.files['file']
        cache.save(filename, file_obj.stream.read())

        # Test in reverse order to fail fast
        for chunk in range(int(flow_total_chunks), 0, -1):
            chunk_name = get_cache_name(flow_identifier, chunk)
            if not cache.exists(chunk_name):
                completed = False
                break

        if completed:
            # Reconstruct the file
            ui_sid = get_cache_name(flow_identifier)
            target_file = os.path.join(TEMP_DIR, ui_sid)
            try:
                os.makedirs(TEMP_DIR)
            except Exception:
                pass

            try:
                os.unlink(target_file)
            except Exception:
                pass

            for chunk in range(int(flow_total_chunks)):
                chunk_name = get_cache_name(flow_identifier, chunk+1)
                with open(target_file, "ab") as t:
                    t.write(cache.get(chunk_name))
                cache.delete(chunk_name)

            # Save the reconstructed file
            with open(target_file, "rb") as t:
                cache.save(ui_sid, t.read())

            os.unlink(target_file)

    return make_api_response({'success': True, 'completed': completed})


# noinspection PyBroadException
@ui_api.route("/start/<ui_sid>/", methods=["POST"])
@api_login(audit=False, allow_readonly=False, require_role=[ROLES.submission_create])
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

    ui_params = request.json
    ui_params['groups'] = kwargs['user']['groups']
    ui_params['quota_item'] = True
    ui_params['submitter'] = user['uname']

    if not Classification.is_accessible(user['classification'], ui_params['classification']):
        return make_api_response({"started": False, "sid": None}, "You cannot start a scan with higher "
                                                                  "classification then you're allowed to see", 403)

    quota_error = check_submission_quota(user)
    if quota_error:
        return make_api_response("", quota_error, 503)

    submit_result = None
    submitted_file = None

    try:
        # Download the file from the cache
        with forge.get_cachestore("flowjs", config) as cache:
            ui_sid = get_cache_name(ui_sid)
            if cache.exists(ui_sid):
                target_dir = os.path.join(TEMP_DIR, ui_sid)
                os.makedirs(target_dir, exist_ok=True)

                target_file = os.path.join(target_dir, ui_params.pop('filename', ui_sid))

                if os.path.exists(target_file):
                    os.unlink(target_file)

                # Save the reconstructed file
                cache.download(ui_sid, target_file)
                submitted_file = target_file

        # Submit the file
        if submitted_file is not None:
            with open(submitted_file, 'rb') as fh:
                if is_cart(fh.read(256)):
                    meta = get_metadata_only(submitted_file)
                    if meta.get('al', {}).get('type', 'unknown') == 'archive/bundle/al':
                        try:
                            submission = import_bundle(submitted_file, allow_incomplete=True, identify=IDENTIFY)
                        except Exception as e:
                            return make_api_response("", err=str(e), status_code=400)
                        return make_api_response({"started": True, "sid": submission['sid']})

            if not ui_params['description']:
                ui_params['description'] = f"Inspection of file: {os.path.basename(submitted_file)}"

            # Submit to dispatcher
            try:
                params = ui_to_submission_params(ui_params)

                # Enforce maximum DTL
                if config.submission.max_dtl > 0:
                    params['ttl'] = min(
                        int(params['ttl']),
                        config.submission.max_dtl) if int(params['ttl']) else config.submission.max_dtl

                submission_obj = Submission({
                    "files": [],
                    "params": params
                })
            except (ValueError, KeyError) as e:
                return make_api_response("", err=str(e), status_code=400)

            try:
                submit_result = SubmissionClient(
                    datastore=STORAGE, filestore=FILESTORE, config=config, identify=IDENTIFY).submit(
                        submission_obj, local_files=[submitted_file])
                submission_received(submission_obj)
            except SubmissionException as e:
                return make_api_response("", err=str(e), status_code=400)

            return make_api_response({"started": True, "sid": submit_result.sid})
        else:
            return make_api_response({"started": False, "sid": None}, "No files where found for ID %s. "
                                                                      "Try again..." % ui_sid, 404)
    finally:
        if submit_result is None:
            decrement_submission_quota(user)

        # Remove file
        if os.path.exists(submitted_file):
            os.unlink(submitted_file)

        # Remove dir
        if os.path.exists(target_dir) and os.path.isdir(target_dir):
            os.rmdir(target_dir)
