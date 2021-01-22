#####################################
# UI ONLY APIs

import glob
import os

from flask import request

from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import TEMP_DIR, TEMP_DIR_CHUNKED, F_READ_CHUNK_SIZE, STORAGE
from assemblyline_ui.helper.service import ui_to_submission_params
from assemblyline_ui.helper.submission import submission_received
from assemblyline_ui.helper.user import check_submission_quota, decrement_submission_quota
from assemblyline.common import forge
from assemblyline.odm.messages.submission import Submission
from assemblyline_core.submission_client import SubmissionClient, SubmissionException

Classification = forge.get_classification()
config = forge.get_config()

SUB_API = 'ui'
ui_api = make_subapi_blueprint(SUB_API, api_version=4)
ui_api._doc = "UI specific operations"


#############################
# Files Functions
def read_chunk(f, chunk_size=F_READ_CHUNK_SIZE):
    while True:
        data = f.read(chunk_size)
        if not data: 
            break
        yield data


# noinspection PyBroadException
def reconstruct_file(mydir, flow_identifier, flow_filename, flow_total_chunks):
    # Reconstruct the file
    target_dir = os.path.join(TEMP_DIR, flow_identifier)
    target_file = os.path.join(target_dir, flow_filename)
    try:
        os.makedirs(target_dir)
    except Exception:
        pass
    
    try:
        os.unlink(target_file)
    except Exception:
        pass
    
    for my_file in range(int(flow_total_chunks)):
        with open(target_file, "ab") as t:
            chunk = str(my_file + 1)
            cur_chunk_file = os.path.join(mydir, "chunk.part%s" % chunk)
            with open(cur_chunk_file, "rb") as s:
                t.write(s.read())
            os.unlink(cur_chunk_file)
    
    os.removedirs(mydir)


def validate_chunks(mydir, flow_total_chunks, flow_chunk_size, flow_total_size):
    if int(flow_total_chunks) > 1:
        last_chunk_size = int(flow_total_size) - ((int(flow_total_chunks) - 1) * int(flow_chunk_size))
    else:
        last_chunk_size = int(flow_total_size)
    
    in_dir_files = os.listdir(mydir)
    
    if len(in_dir_files) != int(flow_total_chunks):
        return False
    
    for i in range(int(flow_total_chunks) - 1):
        myfile = os.path.join(mydir, 'chunk.part' + str(i + 1))
        if not os.path.getsize(myfile) == int(flow_chunk_size):
            return False
        
    myfile = os.path.join(mydir, 'chunk.part' + flow_total_chunks)
    if not os.path.getsize(myfile) == int(last_chunk_size):
        return False
    
    return True
    

##############################
# APIs

# noinspection PyUnusedLocal
@ui_api.route("/flowjs/", methods=["GET"])
@api_login(audit=False, check_xsrf_token=False, allow_readonly=False)
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
    
    mydir = os.path.join(TEMP_DIR_CHUNKED, flow_identifier)
    myfile = os.path.join(mydir, 'chunk.part' + flow_chunk_number)
    if os.path.exists(myfile):
        if os.path.getsize(myfile) == int(flow_current_chunk_size):
            if validate_chunks(mydir, flow_total_chunks, flow_chunk_size, flow_total_size):
                reconstruct_file(mydir, flow_identifier, flow_filename, flow_total_chunks)
            return make_api_response({"exist": True})
        else:
            return make_api_response({"exist": False}, "Chunk wrong size, please resend!", 404)
    else:
        return make_api_response({"exist": False}, "Chunk does not exist, please send it!", 404)


# noinspection PyBroadException, PyUnusedLocal
@ui_api.route("/flowjs/", methods=["POST"])
@api_login(audit=False, check_xsrf_token=False, allow_readonly=False)
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
    flow_filename = request.form.get("flowFilename", None)
    flow_relative_path = request.form.get("flowRelativePath", None)
    flow_total_chunks = request.form.get("flowTotalChunks", None)
    completed = False
    
    if not flow_chunk_number or not flow_chunk_size or not flow_current_chunk_size or not flow_total_size \
            or not flow_identifier or not flow_filename or not flow_relative_path or not flow_total_chunks:
        return make_api_response("", "Required arguments missing. flowChunkNumber, flowChunkSize, "
                                     "flowCurrentChunkSize, flowTotalSize, flowIdentifier, flowFilename, "
                                     "flowRelativePath and flowTotalChunks should always be present.", 412)
    
    mydir = os.path.join(TEMP_DIR_CHUNKED, flow_identifier)
    myfile = os.path.join(mydir, 'chunk.part' + flow_chunk_number)
    try:
        os.makedirs(mydir)
    except Exception:
        pass
    f = open(myfile, "wb")
    file_obj = request.files['file']
    f.write(file_obj.stream.read())
    f.close()

    if validate_chunks(mydir, flow_total_chunks, flow_chunk_size, flow_total_size):
        reconstruct_file(mydir, flow_identifier, flow_filename, flow_total_chunks)
        
        completed = True
        
    return make_api_response({'success': True, 'completed': completed})


# noinspection PyBroadException
@ui_api.route("/start/<ui_sid>/", methods=["POST"])
@api_login(audit=False, allow_readonly=False)
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
    request_files = []
    request_dirs = []
    fnames = []
    try:
        flist = glob.glob(TEMP_DIR + ui_sid + "*")
        if len(flist) > 0:
            # Generate file list
            for fpath in flist:
                request_dirs.append(fpath)
                files = os.listdir(fpath)
                for myfile in files:
                    request_files.append(os.path.join(fpath, myfile))
                    if myfile not in fnames:
                        fnames.append(myfile)
                        
            if not ui_params['description']:
                ui_params['description'] = "Inspection of file%s: %s" % ({True: "s", False: ""}[len(fnames) > 1],
                                                                         ", ".join(fnames))

            # Submit to dispatcher
            try:
                submission_obj = Submission({
                    "files": [],
                    "params": ui_to_submission_params(ui_params)
                })
            except (ValueError, KeyError) as e:
                return make_api_response("", err=str(e), status_code=400)

            with forge.get_filestore() as f_transport:
                try:
                    submit_result = SubmissionClient(datastore=STORAGE, filestore=f_transport,
                                                     config=config).submit(submission_obj,
                                                                           local_files=request_files,
                                                                           cleanup=False)
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

        # Remove files
        for myfile in request_files:
            try:
                os.unlink(myfile)
            except Exception:
                pass
        
        # Remove dirs
        for fpath in request_dirs:
            try:
                os.rmdir(fpath)
            except Exception:
                pass
