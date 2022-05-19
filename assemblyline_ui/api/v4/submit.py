
import json
import os
import shutil

from flask import request

from assemblyline.common.dict_utils import flatten
from assemblyline.common.isotime import iso_to_epoch, epoch_to_iso
from assemblyline.common.str_utils import safe_str
from assemblyline.common.uid import get_random_id
from assemblyline.odm.messages.submission import Submission
from assemblyline_core.submission_client import SubmissionClient, SubmissionException
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import STORAGE, TEMP_SUBMIT_DIR, FILESTORE, config, CLASSIFICATION as Classification, \
    IDENTIFY
from assemblyline_ui.helper.service import ui_to_submission_params
from assemblyline_ui.helper.submission import safe_download, FileTooBigException, InvalidUrlException, \
    ForbiddenLocation, submission_received
from assemblyline_ui.helper.user import check_submission_quota, decrement_submission_quota, load_user_settings

SUB_API = 'submit'
submit_api = make_subapi_blueprint(SUB_API, api_version=4)
submit_api._doc = "Submit files to the system"


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
    quota_error = check_submission_quota(user)
    if quota_error:
        return make_api_response("", quota_error, 503)

    file_info = STORAGE.file.get(sha256, as_obj=False)
    if not file_info:
        return make_api_response({}, f"File {sha256} cannot be found on the server therefore it cannot be resubmitted.",
                                 status_code=404)

    if not Classification.is_accessible(user['classification'], file_info['classification']):
        return make_api_response("", "You are not allowed to re-submit a file that you don't have access to", 403)

    submit_result = None
    try:
        copy_sid = request.args.get('copy_sid', None)
        name = safe_str(request.args.get('name', sha256))

        if copy_sid:
            submission = STORAGE.submission.get(copy_sid, as_obj=False)
        else:
            submission = None

        if submission:
            if not Classification.is_accessible(user['classification'], submission['classification']):
                return make_api_response("",
                                         "You are not allowed to re-submit a submission that you don't have access to",
                                         403)

            submission_params = submission['params']
            submission_params['classification'] = submission['classification']
            expiry = submission['expiry_ts']

        else:
            submission_params = ui_to_submission_params(load_user_settings(user))
            submission_params['classification'] = file_info['classification']
            expiry = file_info['expiry_ts']

        # Calculate original submit time
        if submission_params['ttl'] and expiry:
            submit_time = epoch_to_iso(iso_to_epoch(expiry) - submission_params['ttl'] * 24 * 60 * 60)
        else:
            submit_time = None

        if not FILESTORE.exists(sha256):
            return make_api_response({}, "File %s cannot be found on the server therefore it cannot be resubmitted."
                                     % sha256, status_code=404)

        files = [{'name': name, 'sha256': sha256, 'size': file_info['size']}]

        submission_params['submitter'] = user['uname']
        submission_params['quota_item'] = True
        if 'priority' not in submission_params:
            submission_params['priority'] = 500
        submission_params['description'] = "Resubmit %s for Dynamic Analysis" % name
        if "Dynamic Analysis" not in submission_params['services']['selected']:
            submission_params['services']['selected'].append("Dynamic Analysis")

        try:
            submission_obj = Submission({
                "files": files,
                "params": submission_params,
                "time": submit_time
            })
        except (ValueError, KeyError) as e:
            return make_api_response("", err=str(e), status_code=400)

        submit_result = SubmissionClient(datastore=STORAGE, filestore=FILESTORE,
                                         config=config, identify=IDENTIFY).submit(submission_obj)
        submission_received(submission_obj)
        return make_api_response(submit_result.as_primitives())

    except SubmissionException as e:
        return make_api_response("", err=str(e), status_code=400)
    finally:
        if submit_result is None:
            decrement_submission_quota(user)


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
    quota_error = check_submission_quota(user)
    if quota_error:
        return make_api_response("", quota_error, 503)

    submit_result = None
    try:
        submission = STORAGE.submission.get(sid, as_obj=False)

        if submission:
            if not Classification.is_accessible(user['classification'], submission['classification']):
                return make_api_response("",
                                         "You are not allowed to re-submit a submission that you don't have access to",
                                         403)

            submission_params = submission['params']
            submission_params['classification'] = submission['classification']
        else:
            return make_api_response({}, "Submission %s does not exists." % sid, status_code=404)

        submission_params['submitter'] = user['uname']
        submission_params['quota_item'] = True
        submission_params['description'] = "Resubmit %s for analysis" % ", ".join([x['name']
                                                                                   for x in submission["files"]])

        # Calculate original submit time
        if submission_params['ttl'] and submission['expiry_ts']:
            submit_time = epoch_to_iso(iso_to_epoch(submission['expiry_ts']) - submission_params['ttl'] * 24 * 60 * 60)
        else:
            submit_time = None

        try:
            submission_obj = Submission({
                "files": submission["files"],
                "metadata": submission['metadata'],
                "params": submission_params,
                "time": submit_time
            })
        except (ValueError, KeyError) as e:
            return make_api_response("", err=str(e), status_code=400)

        submit_result = SubmissionClient(datastore=STORAGE, filestore=FILESTORE,
                                         config=config, identify=IDENTIFY).submit(submission_obj)
        submission_received(submission_obj)

        return make_api_response(submit_result.as_primitives())
    except SubmissionException as e:
        return make_api_response("", err=str(e), status_code=400)
    finally:
        if submit_result is None:
            decrement_submission_quota(user)


# noinspection PyBroadException
@submit_api.route("/", methods=["POST"])
@api_login(audit=False, required_priv=['W'], allow_readonly=False)
def submit(**kwargs):
    """
    Submit a single file, sha256 or url for analysis

        Note 1:
            If you are submitting a sh256 or a URL, you must use the application/json encoding and one of
            sha256 or url parameters must be included in the data block.

        Note 2:
            If you are submitting a file directly, you have to use multipart/form-data encoding this
            was done to reduce the memory footprint and speedup file transfers
             ** Read documentation of mime multipart standard if your library does not support it**

            The multipart/form-data for sending binary has two parts:
                - The first part contains a JSON dump of the optional params and uses the name 'json'
                - The last part conatins the file binary, uses the name 'bin' and includes a filename

    Variables:
    None

    Arguments:
    None

    Data Block (SHA256 or URL):
    {
      // REQUIRED: One of the two following
      "sha256": "123...DEF",      # SHA256 hash of the file already in the datastore
      "url": "http://...",        # Url to fetch the file from

      // OPTIONAL VALUES
      "name": "file.exe",         # Name of the file to scan otherwise the sha256 or base file of the url

      "metadata": {               # Submission metadata
        "key": val,                 # Key/Value pair metadata values
      },

      "params": {                 # Submission parameters
        "key": val,                 # Key/Value pair for params that different then defaults
      },                            # Default params can be fetch at /api/v3/user/submission_params/<user>/
    }

    Data Block (Binary):

    --0b34a3c50d3c02dd804a172329a0b2aa               <-- Randomly generated boundary for this http request
    Content-Disposition: form-data; name="json"      <-- JSON data blob part (only previous optional values valid)

    {"metadata": {"hello": "world"}}
    --0b34a3c50d3c02dd804a172329a0b2aa               <-- Switch to next part, file part
    Content-Disposition: form-data; name="bin"; filename="name_of_the_file_to_scan.bin"

    <BINARY DATA OF THE FILE TO SCAN... DOES NOT NEED TO BE ENCODDED>

    --0b34a3c50d3c02dd804a172329a0b2aa--             <-- End of HTTP transmission


    Result example:
    <Submission message object as a json dictionary>
    """
    user = kwargs['user']
    out_dir = os.path.join(TEMP_SUBMIT_DIR, get_random_id())

    quota_error = check_submission_quota(user)
    if quota_error:
        return make_api_response("", quota_error, 503)

    submit_result = None
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
        elif 'application/json' in request.content_type:
            data = request.json
            binary = None
            sha256 = data.get('sha256', None)
            url = data.get('url', None)
            name = data.get("name", None) or sha256 or os.path.basename(url) or None
        else:
            return make_api_response({}, "Invalid content type", 400)

        if data is None:
            return make_api_response({}, "Missing data block", 400)

        if not name:
            return make_api_response({}, "Filename missing", 400)

        name = safe_str(os.path.basename(name))
        if not name:
            return make_api_response({}, "Invalid filename", 400)

        # Create task object
        if "ui_params" in data:
            s_params = ui_to_submission_params(data['ui_params'])
        else:
            s_params = ui_to_submission_params(load_user_settings(user))

        s_params.update(data.get("params", {}))
        if 'groups' not in s_params:
            s_params['groups'] = user['groups']

        s_params['quota_item'] = True
        s_params['submitter'] = user['uname']
        if not s_params['description']:
            s_params['description'] = "Inspection of file: %s" % name

        # Enforce maximum DTL
        if config.submission.max_dtl > 0:
            s_params['ttl'] = min(
                int(s_params['ttl']),
                config.submission.max_dtl) if int(s_params['ttl']) else config.submission.max_dtl

        if not Classification.is_accessible(user['classification'], s_params['classification']):
            return make_api_response({}, "You cannot start a scan with higher "
                                     "classification then you're allowed to see", 400)

        # Prepare the output directory
        try:
            os.makedirs(out_dir)
        except Exception:
            pass
        out_file = os.path.join(out_dir, name)

        # Get the output file
        extra_meta = {}
        if not binary:
            if sha256:
                fileinfo = STORAGE.file.get_if_exists(sha256, as_obj=False,
                                                      archive_access=config.datastore.ilm.update_archive)
                if FILESTORE.exists(sha256):
                    if fileinfo:
                        if not Classification.is_accessible(user['classification'], fileinfo['classification']):
                            return make_api_response({}, "SHA256 does not exist in our datastore", 404)
                        else:
                            # File's classification must be applied at a minimum
                            s_params['classification'] = Classification.max_classification(s_params['classification'],
                                                                                           fileinfo['classification'])

                    # File exists in the filestore and the user has appropriate file access
                    FILESTORE.download(sha256, out_file)
                else:
                    return make_api_response({}, "SHA256 does not exist in our datastore", 404)
            else:
                if url:
                    if not config.ui.allow_url_submissions:
                        return make_api_response({}, "URL submissions are disabled in this system", 400)

                    try:
                        safe_download(url, out_file)
                        extra_meta['submitted_url'] = url
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
                my_file.write(binary.read())

        try:
            metadata = flatten(data.get('metadata', {}))
            metadata.update(extra_meta)

            submission_obj = Submission({
                "files": [],
                "metadata": metadata,
                "params": s_params
            })
        except (ValueError, KeyError) as e:
            return make_api_response("", err=str(e), status_code=400)

        # Submit the task to the system
        try:
            submit_result = SubmissionClient(datastore=STORAGE, filestore=FILESTORE, config=config, identify=IDENTIFY)\
                .submit(submission_obj, local_files=[out_file])
            submission_received(submission_obj)
        except SubmissionException as e:
            return make_api_response("", err=str(e), status_code=400)

        return make_api_response(submit_result.as_primitives())

    finally:
        if submit_result is None:
            decrement_submission_quota(user)

        try:
            # noinspection PyUnboundLocalVariable
            os.unlink(out_file)
        except Exception:
            pass

        try:
            shutil.rmtree(out_dir, ignore_errors=True)
        except Exception:
            pass
