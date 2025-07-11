import os
import shutil
import tempfile
from typing import Tuple, Union

from assemblyline_core.submission_client import SubmissionClient, SubmissionException
from flask import request

from assemblyline.common.constants import MAX_PRIORITY, PRIORITIES
from assemblyline.common.str_utils import safe_str
from assemblyline.odm.messages.submission import Submission
from assemblyline.odm.models.user import ROLES
from assemblyline_ui.api.base import (
    Response,
    api_login,
    make_api_response,
    make_subapi_blueprint,
)
from assemblyline_ui.config import (
    ARCHIVESTORE,
    FILESTORE,
    IDENTIFY,
    LOGGER,
    STORAGE,
    SUBMISSION_PROFILES,
    config,
)
from assemblyline_ui.config import CLASSIFICATION as Classification
from assemblyline_ui.helper.submission import (
    FileTooBigException,
    init_submission,
    submission_received,
    update_submission_parameters,
)
from assemblyline_ui.helper.user import (
    check_submission_quota,
    decrement_submission_quota,
)

SUB_API = 'submit'
submit_api = make_subapi_blueprint(SUB_API, api_version=4)
submit_api._doc = "Submit files to the system"


# Since everything the submission client needs is already being initialized
# at the global scope, we can create the submission client object at that scope as well
submission_client = SubmissionClient(datastore=STORAGE, filestore=FILESTORE, config=config, identify=IDENTIFY)


def create_resubmission_task(sha256: str, user: dict, copy_sid: str = None, name: str = None, profile: str = None, **kwargs) ->Union[Tuple[Submission, int], Response]:
    # Check if we've reached the quotas
    quota_error = check_submission_quota(user)
    if quota_error:
        return make_api_response("", quota_error, 503)

    file_info = STORAGE.file.get(sha256, as_obj=False)
    if not file_info:
        return make_api_response({}, f"File {sha256} cannot be found on the server therefore it cannot be resubmitted.",
                                 status_code=404)

    # Check if this pertains to a file that's been archived and it's not currently in the filestore
    if file_info.get('from_archive', False) and not FILESTORE.exists(sha256):
        # If the file in question doesn't exist in the filestore, then make a copy from the archivestore
        FILESTORE.put(sha256, content=ARCHIVESTORE.get(sha256), location="far")

    if not Classification.is_accessible(user['classification'], file_info['classification']):
        return make_api_response("", "You are not allowed to re-submit a file that you don't have access to", 403)

    metadata = {}
    copy_sid = request.args.get('copy_sid', None)
    if copy_sid:
        submission = STORAGE.submission.get(copy_sid, as_obj=False)
    else:
        submission = None

    submission_params = {
        "services": {
            "selected": [],
            "excluded": []
        },
    }
    if submission:
        if not Classification.is_accessible(user['classification'], submission['classification']):
            return make_api_response("",
                                        "You are not allowed to re-submit a submission that you don't have access to",
                                        403)

        submission_params = submission['params']
        submission_params['classification'] = submission['classification']
        expiry = submission['expiry_ts']
        metadata = submission['metadata']

    else:
        # Preserve the classification and expiration of the original file when resubmitting
        submission_params['classification'] = file_info['classification']
        expiry = file_info['expiry_ts']

    if not FILESTORE.exists(sha256):
        if ARCHIVESTORE and ARCHIVESTORE != FILESTORE and \
                ROLES.archive_download in user['roles'] and ARCHIVESTORE.exists(sha256):

            # File exists in the archivestore, copying it to the filestore
            with tempfile.NamedTemporaryFile() as buf:
                ARCHIVESTORE.download(sha256, buf.name)
                FILESTORE.upload(buf.name, sha256, location='far')

        else:
            return make_api_response({}, "File %s cannot be found on the server therefore it cannot be resubmitted."
                                        % sha256, status_code=404)


    if (file_info["type"].startswith("uri/") and "uri_info" in file_info and "uri" in file_info["uri_info"]):
        name = safe_str(file_info["uri_info"]["uri"])
    else:
        name = safe_str(request.args.get('name', sha256))
    description_prefix = f"Resubmit {name}"

    files = [{'name': name, 'sha256': sha256, 'size': file_info['size']}]

    if profile:
        submission_params['submission_profile'] = profile

        # Omit the service selection from the submission and service_spec to use the profile's settings
        submission_params.pop("services", None)
        submission_params.pop("service_spec", None)

        # Preserve the classification of the original submission
        classification = submission_params['classification']

        submission_profiles = (STORAGE.user_settings.get(user['uname'], as_obj=False) or {}).get('submission_profiles', {})
        submission_params = update_submission_parameters(submission_params, user, submission_profiles)
        submission_params['description'] = f"{description_prefix} with {SUBMISSION_PROFILES[profile].display_name}"
        submission_params['classification'] = classification

    else:
        # Only append Dynamic Analysis as a selected service and set the priority
        if 'priority' not in submission_params:
            submission_params['priority'] = 500
        if "Dynamic Analysis" not in submission_params['services']['selected']:
            submission_params['services']['selected'].append("Dynamic Analysis")
        submission_params['services'].setdefault('excluded', [])
        if "Dynamic Analysis" in submission_params['services']['excluded']:
            submission_params['services']['excluded'].remove("Dynamic Analysis")

        # Ensure submission priority stays within the range of user priorities
        submission_params['priority'] = max(min(submission_params['priority'], MAX_PRIORITY), PRIORITIES['user-low'])
        submission_params['description'] = f"{description_prefix} for Dynamic Analysis"

    submission_params['submitter'] = user['uname']
    submission_params['quota_item'] = True

    try:
        return Submission({ "files": files, "params": submission_params, "metadata": metadata}), expiry
    except (ValueError, KeyError) as e:
        return make_api_response("", err=str(e), status_code=400)

# noinspection PyUnusedLocal
@submit_api.route("/<profile>/<sha256>/", methods=["PUT"])
@api_login(allow_readonly=False, require_role=[ROLES.submission_create], count_toward_quota=False)
def resubmit_with_profile(profile, sha256, *args, **kwargs):
    """
    Resubmit a file using a submission profile

    Variables:
    profile        => Submission profile to be used in new submission
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

    submit_result = None
    try:
        ret_value = create_resubmission_task(sha256=sha256, profile=profile, user=user, **request.args)
        if isinstance(ret_value, Response):
            # Forward error response back to user
            return ret_value
        else:
            # Otherwise we got submission object with an expiry
            submission_obj, expiry = ret_value
            submit_result = submission_client.submit(submission_obj, expiry=expiry)
            submission_received(submission_obj)
            return make_api_response(submit_result.as_primitives())
    except SubmissionException as e:
        return make_api_response("", err=str(e), status_code=400)
    finally:
        if submit_result is None:
            # We had an error during the submission, release the quotas for the user
            decrement_submission_quota(user)


# noinspection PyUnusedLocal
@submit_api.route("/dynamic/<sha256>/", methods=["GET"])
@api_login(allow_readonly=False, require_role=[ROLES.submission_create], count_toward_quota=False)
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
    submit_result = None
    try:
        ret_value = create_resubmission_task(sha256=sha256, user=user, **request.args)
        if isinstance(ret_value, Response):
            # Forward error response back to user
            return ret_value
        else:
            # Otherwise we got submission object with an expiry
            submission_obj, expiry = ret_value
            submit_result = submission_client.submit(submission_obj, expiry=expiry)
            submission_received(submission_obj)
            return make_api_response(submit_result.as_primitives())
    except SubmissionException as e:
        return make_api_response("", err=str(e), status_code=400)
    finally:
        if submit_result is None:
            # We had an error during the submission, release the quotas for the user
            decrement_submission_quota(user)


# noinspection PyUnusedLocal
@submit_api.route("/resubmit/<sid>/", methods=["GET"])
@api_login(allow_readonly=False, require_role=[ROLES.submission_create], count_toward_quota=False)
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

    # Check if we've reached the quotas
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

        # Ensure the files associated in the submission are present in the system
        for file in submission['files']:
            sha256 = file['sha256']
            file_info = STORAGE.file.get(sha256, as_obj=False)
            # Check if this pertains to a file that's been archived and it's not currently in the filestore
            if file_info.get('from_archive', False) and not FILESTORE.exists(sha256):
                # If the file in question doesn't exist in the filestore, then make a copy from the archivestore
                FILESTORE.put(sha256, content=ARCHIVESTORE.get(sha256), location="far")

        try:
            submission_obj = Submission({
                "files": submission["files"],
                "metadata": submission['metadata'],
                "params": submission_params,
            })
        except (ValueError, KeyError) as e:
            return make_api_response("", err=str(e), status_code=400)

        submit_result = submission_client.submit(submission_obj, expiry=submission['expiry_ts'])
        submission_received(submission_obj)

        return make_api_response(submit_result.as_primitives())
    except SubmissionException as e:
        return make_api_response("", err=str(e), status_code=400)
    finally:
        if submit_result is None:
            # We had an error during the submission, release the quotas for the user
            decrement_submission_quota(user)


# noinspection PyBroadException
@submit_api.route("/", methods=["POST"])
@api_login(allow_readonly=False, require_role=[ROLES.submission_create], count_toward_quota=False)
def submit(**kwargs):
    """
    Submit a single file, sha256 or url for analysis

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

    Variables:
    None

    Arguments:
    None

    Data Block (String Input):
    {
      // REQUIRED: One of the two following
      "<string_type>": "<string_value>",        # Key-Pair indicating a method to fetch a file and the related input

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
      },                                        # Default params can be fetch at /api/v4/user/submission_params/<user>/
    }

    Data Block (Binary):

    --0b34a3c50d3c02dd804a172329a0b2aa               <-- Randomly generated boundary for this http request
    Content-Disposition: form-data; name="json"      <-- JSON data blob part (only previous optional values valid)

    {"metadata": {"hello": "world"}}
    --0b34a3c50d3c02dd804a172329a0b2aa               <-- Switch to next part, file part
    Content-Disposition: form-data; name="bin"; filename="name_of_the_file_to_scan.bin"

    <BINARY DATA OF THE FILE TO SCAN... DOES NOT NEED TO BE ENCODED>

    --0b34a3c50d3c02dd804a172329a0b2aa--             <-- End of HTTP transmission


    Result example:
    <Submission message object as a json dictionary>
    """
    user = kwargs['user']

    # Check if we've reached the quotas
    quota_error = check_submission_quota(user)
    if quota_error:
        return make_api_response("", quota_error, 503)

    submit_result = None
    try:
        try:
            # Initialize submission validation process
            _, out_file, name, _, s_params, metadata = init_submission(request, user, endpoint="submit")
        except FileTooBigException as e:
            LOGGER.warning(f"[{user['uname']}] {e}")
            return make_api_response({}, str(e), 413)
        except FileNotFoundError as e:
            return make_api_response({}, str(e), 404)
        except (PermissionError, Exception) as e:
            return make_api_response({}, str(e), 400)

        # Update submission parameters relative to the endpoint
        s_params.update({
            # Submission counts toward their quota
            'quota_item': True,
            # Set max extracted/supplementary if missing from request
            'max_extracted': s_params.get('max_extracted', config.submission.default_max_extracted),
            'max_supplementary': s_params.get('max_supplementary', config.submission.default_max_supplementary)
        })

        # Create a submission object for tasking
        try:
            submission_obj = Submission({
                "files": [],
                "metadata": metadata,
                "params": s_params
            })
        except (ValueError, KeyError) as e:
            return make_api_response("", err=str(e), status_code=400)

        # Submit the task to the system
        try:
            submit_result = submission_client.submit(submission_obj, local_files=[(name, out_file)])
            submission_received(submission_obj)
        except SubmissionException as e:
            return make_api_response("", err=str(e), status_code=400)

        return make_api_response(submit_result.as_primitives())

    finally:
        if submit_result is None:
            # We had an error during the submission, release the quotas for the user
            decrement_submission_quota(user)

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
