
import base64
import baseconv
import os
import shutil
import uuid

from flask import request

from al_core.submission_client import SubmissionClient, SubmissionException
from al_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from al_ui.config import STORAGE, TEMP_SUBMIT_DIR
from al_ui.helper.submission import safe_download, FileTooBigException, InvalidUrlException, ForbiddenLocation
from al_ui.helper.user import check_submission_quota, get_default_user_settings
from al_ui.helper.service import ui_to_submission_params
from assemblyline.common import forge
from assemblyline.odm.messages.submission import Submission

Classification = forge.get_classification()
config = forge.get_config()

SUB_API = 'submit'
submit_api = make_subapi_blueprint(SUB_API, api_version=4)
submit_api._doc = "Submit files to the system"


# # noinspection PyUnusedLocal
# @submit_api.route("/checkexists/", methods=["POST"])
# @api_login(audit=False, required_priv=['W'], allow_readonly=False)
# def check_sha256_exists(*args, **kwargs):
#     """
#     Check if the the provided Resource locators exist in the
#     system or not.
#
#     Variables:
#     None
#
#     Arguments:
#     None
#
#     Data Block (REQUIRED):
#     ["sha2561", sha2562]    # List of sha256s (SHA256)
#
#     Result example:
#     {
#      "existing": [],  # List of existing sha256s
#      "missing": []    # List of missing sha256s
#      }
#     """
#     sha256s_to_check = request.json
#     if type(sha256s_to_check) != list:
#         return make_api_response("", "Expecting a list of sha256s", 403)
#
#     with forge.get_filestore() as f_transport:
#         check_results = SubmissionWrapper.check_exists(f_transport, sha256s_to_check)
#     return make_api_response(check_results)
#
#
# # noinspection PyUnusedLocal
# @submit_api.route("/identify/", methods=["POST"])
# @api_login(audit=False, required_priv=['W'], allow_readonly=False)
# def identify_supplementary_files(*args, **kwargs):
#     """
#     Ask the UI to create file entries for supplementary files.
#
#     Variables:
#     None
#
#     Arguments:
#     None
#
#     Data Block (REQUIRED):
#     {
#      "1":                                   # File ID
#        {"sha256": "982...077",                  # SHA256 of the file
#         "classification": "UNRESTRICTED",       # Other KW args to be passed to function
#         "ttl": 30 },                            # Days to live for the file
#      ...
#     }
#
#     Result example:
#     {
#      "1": {                       # File ID
#        "status": "success",         # API result status for the file ("success", "failed")
#        "fileinfo": {}               # File information Block
#        }, ...
#     }
#     """
#     user = kwargs['user']
#     submit_requests = request.json
#     submit_results = {}
#     user_params = load_user_settings(user)
#     for key, submit in submit_requests.iteritems():
#         submit['submitter'] = user['uname']
#         if 'classification' not in submit:
#             submit['classification'] = user_params['classification']
#         with forge.get_filestore() as f_transport:
#             file_info = SubmissionWrapper.identify(f_transport, STORAGE, **submit)
#         if file_info:
#             submit_result = {"status": "succeeded", "fileinfo": file_info}
#         else:
#             submit_result = {"status": "failed", "fileinfo": {}}
#         submit_results[key] = submit_result
#     return make_api_response(submit_results)
#
#
# # noinspection PyUnusedLocal
# @submit_api.route("/presubmit/", methods=["POST"])
# @api_login(audit=False, required_priv=['W'], allow_readonly=False)
# def pre_submission(*args, **kwargs):
#     """
#     Perform a presubmit of a list of local files. This is the first
#     stage for a batch submit of files.
#
#     Variables:
#     None
#
#     Arguments:
#     None
#
#     Data Block (REQUIRED):
#     {
#      "1":                                       # File ID
#        {"sha256": "982...077",                    # SHA256 of the file
#         "path": "/local/file/path", },            # Path of the file
#      ... }
#
#     Result example:
#     {
#      "1":                                       # File ID
#        {"exists": false,                          # Does the file already exist?
#         "succeeded": true,                        # Is the result for this file accurate?
#         "filestore": "TransportFTP:transport.al", # File Transport method/url
#         "kwargs":                                 # Extra (** kwargs)
#           {"path": "/local/file path"},             # Path to the file
#         "upload_path": "/remote/upload/path",     # Where to upload if missing
#         "sha256": "982...077"},                   # SHA256 of the file
#     }
#     """
#     presubmit_requests = request.json
#     presubmit_results = {}
#     for key, presubmit in presubmit_requests.iteritems():
#         succeeded = True
#         presubmit_result = {}
#         try:
#             with forge.get_filestore() as f_transport:
#                 presubmit_result = SubmissionWrapper.presubmit(f_transport, **presubmit)
#         except Exception as e:
#             succeeded = False
#             msg = 'Failed to presubmit for {0}:{1}'.format(key, e)
#             presubmit_result['error'] = msg
#         presubmit_result['succeeded'] = succeeded
#         presubmit_results[key] = presubmit_result
#
#     return make_api_response(presubmit_results)


# noinspection PyUnusedLocal
@submit_api.route("/dynamic/<sha256>/", methods=["GET"])
@api_login(required_priv=['W'], allow_readonly=False)
def resubmit_for_dynamic(sha256, *args, **kwargs):
    """
    Resubmit a file for dynamic analysis
    
    Variables:
    sha256         => Resource locator (SHA256)
    
    Arguments (Optional): 
    copy_sid    => Mimic the attributes of this SID.
    name        => Name of the file for the submission
    
    Data Block:
    None
    
    Result example:
    # Submission message object as a json dictionary
    """
    user = kwargs['user']
    copy_sid = request.args.get('copy_sid', None)
    name = request.args.get('name', sha256)
    
    if copy_sid:
        submission = STORAGE.submission.get(copy_sid, as_obj=False)
    else:
        submission = None
        
    if submission:
        if not Classification.is_accessible(user['classification'], submission['classification']):
            return make_api_response("", "You are not allowed to re-submit a submission that you don't have access to",
                                     403)

        submission_params = submission['params']
        submission_params['classification'] = submission['classification']
        
    else:
        submission_params = ui_to_submission_params(STORAGE.user_settings.get(user['uname'], as_obj=False))

    with forge.get_filestore() as f_transport:
        if not f_transport.exists(sha256):
            return make_api_response({}, "File %s cannot be found on the server therefore it cannot be resubmitted."
                                         % sha256, status_code=404)

        files = [{'name': name, 'sha256': sha256}]

        submission_params['submitter'] = user['uname']
        if 'priority' not in submission_params:
            submission_params['priority'] = 500
        submission_params['description'] = "Resubmit %s for Dynamic Analysis" % name
        if "Dynamic Analysis" not in submission_params['services']['selected']:
            submission_params['services']['selected'].append("Dynamic Analysis")

        try:
            submission_obj = Submission({
                "files": files,
                "params": submission_params
            })
        except (ValueError, KeyError) as e:
            return make_api_response("", err=str(e), status_code=400)

        try:
            submit_result = SubmissionClient(datastore=STORAGE, filestore=f_transport,
                                             config=config).submit(submission_obj)
        except SubmissionException as e:
            return make_api_response("", err=str(e), status_code=400)

    return make_api_response(submit_result.as_primitives())


# noinspection PyUnusedLocal
@submit_api.route("/resubmit/<sid>/", methods=["GET"])
@api_login(required_priv=['W'], allow_readonly=False)
def resubmit_submission_for_analysis(sid, *args, **kwargs):
    """
    Resubmit a submission for analysis with the exact same parameters as before

    Variables:
    sid         => Submission ID to re-submit

    Arguments:
    None

    Data Block:
    None

    Result example:
    # Submission message object as a json dictionary
    """
    user = kwargs['user']
    submission = STORAGE.submission.get(sid, as_obj=False)

    if submission:
        if not Classification.is_accessible(user['classification'], submission['classification']):
            return make_api_response("", "You are not allowed to re-submit a submission that you don't have access to",
                                     403)

        submission_params = submission['params']
        submission_params['classification'] = submission['classification']
    else:
        return make_api_response({}, "Submission %s does not exists." % sid, status_code=404)

    submission_params['submitter'] = user['uname']
    submission_params['description'] = "Resubmit %s for analysis" % ", ".join([x['name'] for x in submission["files"]])

    try:
        submission_obj = Submission({
            "files": submission["files"],
            "params": submission_params
        })
    except (ValueError, KeyError) as e:
        return make_api_response("", err=str(e), status_code=400)

    with forge.get_filestore() as f_transport:
        try:
            submit_result = SubmissionClient(datastore=STORAGE, filestore=f_transport,
                                             config=config).submit(submission_obj)
        except SubmissionException as e:
            return make_api_response("", err=str(e), status_code=400)


    return make_api_response(submit_result.as_primitives())


# # noinspection PyUnusedLocal
# @submit_api.route("/start/", methods=["POST"])
# @api_login(audit=False, required_priv=['W'], allow_readonly=False)
# def start_submission(*args, **kwargs):
#     """
#     Submit a batch of files at the same time. This assumes that the
#     presubmit API was called first to verify if the files are indeed
#     already on the system and that the missing files where uploaded
#     using the given transport and upload location returned by the
#     presubmit API.
#
#     Variables:
#     None
#
#     Arguments:
#     None
#
#     Data Block (REQUIRED):
#     {
#      "1":                         # File ID
#        {"sha256": "982...077",      # SHA256 of the file
#         "path": "/local/file/path", # Path of the file
#         "KEYWORD": ARG, },          # Any other KWARGS for the submission block
#      ... }
#
#     Result example:
#     {
#      "1":                         # File ID
#        "submission":{},             # Submission Block
#        "request": {},               # Request Block
#        "times": {},                 # Timing Block
#        "state": "submitted",        # Submission state
#        "services": {},              # Service selection Block
#        "fileinfo": {}               # File information Block
#        }, ...
#     }
#     """
#     user = kwargs['user']
#
#     submit_requests = request.json
#
#     check_submission_quota(user, len(submit_requests))
#
#     submit_results = {}
#     user_params = load_user_settings(user)
#     for key, submit in submit_requests.iteritems():
#         submit['submitter'] = user['uname']
#         submit['quota_item'] = True
#         path = submit.get('path', './path/missing')
#         if 'classification' not in submit:
#             submit['classification'] = user_params['classification']
#         if 'groups' not in submit:
#             submit['groups'] = user['groups']
#         if 'description' not in submit:
#             submit['description'] = "Inspection of file: %s" % path
#         if 'selected'not in submit:
#             submit['selected'] = simplify_services(user_params["services"])
#         with forge.get_filestore() as f_transport:
#             submit_result = SubmissionWrapper.submit(f_transport, STORAGE, **submit)
#         submit_results[key] = submit_result
#     return make_api_response(submit_results)


# noinspection PyBroadException
@submit_api.route("/", methods=["POST"])
@api_login(audit=False, required_priv=['W'], allow_readonly=False)
def submit(**kwargs):
    """
    Submit a single file or url
    
    Variables:
    None
    
    Arguments: 
    None
    
    Data Block (REQUIRED): 
    {
     "name": "file.exe",     # Name of the file
     "binary": "A24AB..==",  # Base64 encoded file binary
     "sha256": "123...DEF",  # SHA256 hash of the file if you know the file is already in the datastore
     "url": "http://...",    # Url to fetch the file from

     "metadata": {           # Submission metadata
         "key": val,            # Key/Value pair metadata values
         },

     "params": {             # Submission parameters
         "key": val,            # Key/Value pair for params that different then defaults
         },                     # Default params can be fetch at /api/v3/user/submission_params/<user>/

     "ui_params": {          # UI submission parameters (Only used by UI)
         "key": val,            # UI Key/Value pair of the parameters for the submission
         }
    }
    
    Result example:
    # Submission message object as a json dictionary
    """
    user = kwargs['user']
    check_submission_quota(user)
        
    out_dir = os.path.join(TEMP_SUBMIT_DIR, baseconv.base62.encode(uuid.uuid4().int))

    with forge.get_filestore() as f_transport:
        try:
            data = request.json
            if not data:
                return make_api_response({}, "Missing data block", 400)

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

            # Create task object
            if "ui_params" in data:
                s_params = ui_to_submission_params(data['ui_params'])
            else:
                s_params = ui_to_submission_params(STORAGE.user_settings.get(user['uname'], as_obj=False))

            if not s_params:
                s_params = get_default_user_settings(user)

            s_params.update(data.get("params", {}))
            if 'groups' not in s_params:
                s_params['groups'] = user['groups']

            s_params['quota_item'] = True
            s_params['submitter'] = user['uname']
            if not s_params['description']:
                s_params['description'] = "Inspection of file: %s" % name

            try:
                submission_obj = Submission({
                    "files": [],
                    "metadata": data.get('metadata', {}),
                    "params": s_params
                })
            except (ValueError, KeyError) as e:
                return make_api_response("", err=str(e), status_code=400)

            try:
                result = SubmissionClient(datastore=STORAGE, filestore=f_transport,
                                          config=config).submit(submission_obj, local_files=[out_file], cleanup=False)
            except SubmissionException as e:
                return make_api_response("", err=str(e), status_code=400)

            return make_api_response(result.as_primitives())

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
