import base64
import hashlib
import io
import json
import os
import shutil
import tempfile
from typing import Tuple, Union

from assemblyline_core.submission_client import SubmissionClient, SubmissionException
from flask import request

from assemblyline.common.constants import MAX_PRIORITY, PRIORITIES
from assemblyline.common.dict_utils import flatten
from assemblyline.common.str_utils import safe_str
from assemblyline.common.uid import get_random_id
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
    TEMP_SUBMIT_DIR,
    config,
    metadata_validator,
)
from assemblyline_ui.config import CLASSIFICATION as Classification
from assemblyline_ui.helper.service import ui_to_submission_params
from assemblyline_ui.helper.submission import (
    FETCH_METHODS,
    URL_GENERATORS,
    FileTooBigException,
    fetch_file,
    refang_url,
    submission_received,
    update_submission_parameters,
)
from assemblyline_ui.helper.user import (
    check_submission_quota,
    decrement_submission_quota,
    load_user_settings,
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

    if not Classification.is_accessible(user['classification'], file_info['classification']):
        return make_api_response("", "You are not allowed to re-submit a file that you don't have access to", 403)

    metadata = {}
    copy_sid = request.args.get('copy_sid', None)
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
        metadata = submission['metadata']

    else:
        submission_params = ui_to_submission_params(load_user_settings(user))
        submission_params['classification'] = file_info['classification']
        expiry = file_info['expiry_ts']

        # Ignore external sources
        submission_params.pop('default_external_sources', None)

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
        # Obtain any settings from the user and apply them to the submission
        user_settings = STORAGE.user_settings.get(user['uname'], as_obj=False)
        if user_settings:
            # Reuse existing settings for specified profile
            profile_params = user_settings['submission_profiles'].get(profile, {})
        else:
            # Otherwise default to what's set for the profile at the configuration-level
            profile_params = {}
        profile_params['submission_profile'] = profile

        submission_params = update_submission_parameters(submission_params, profile_params, user)
        submission_params['description'] = f"{description_prefix} with {SUBMISSION_PROFILES[profile].display_name}"

    else:
        # Only append Dynamic Analysis as a selected service and set the priority
        if 'priority' not in submission_params:
            submission_params['priority'] = 500
        if "Dynamic Analysis" not in submission_params['services']['selected']:
            submission_params['services']['selected'].append("Dynamic Analysis")

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
@submit_api.route("/<profile>/<sha256>/", methods=["GET"])
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
                - The last part conatins the file binary, uses the name 'bin' and includes a filename

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

      // OPTIONAL VALUES
      "name": "file.exe",                   # Name of the file to scan otherwise the sha256 or base file of the url

      "submission_profile": "static",       # Name of submission profile to use

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
    out_dir = os.path.join(TEMP_SUBMIT_DIR, get_random_id())

    # Check if we've reached the quotas
    quota_error = check_submission_quota(user)
    if quota_error:
        return make_api_response("", quota_error, 503)

    submit_result = None
    string_type = None
    string_value = None
    try:
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

            if string_type in URL_GENERATORS:
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
        default_description = f"Inspection of {'URL' if string_type in URL_GENERATORS else 'file'}: {name}"

        if not name:
            return make_api_response({}, "Filename missing", 400)

        # Load in the user's settings in case it wasn't provided from the UI
        # Ensure the `default_external_sources` are popped before converting UI params to submission params
        user_settings = data['ui_params'] if "ui_params" in data else load_user_settings(user)
        default_external_sources = user_settings.pop('default_external_sources', [])

        # Create task object
        if (ROLES.submission_customize in user['roles']) or "ui_params" in data:
            s_params = ui_to_submission_params(user_settings)
        else:
            s_params = {"submission_profile": user_settings.get("preferred_submission_profile")}

        # Update submission parameters as specified by the user
        try:
            s_params = update_submission_parameters(s_params, data, user)
        except Exception as e:
            return make_api_response({}, str(e), 400)


        default_external_sources = s_params.pop('default_external_sources', []) or default_external_sources
        if 'groups' not in s_params:
            s_params['groups'] = [g for g in user['groups'] if g in s_params['classification']]

        s_params['quota_item'] = True
        s_params['submitter'] = user['uname']

        # Set max extracted/supplementary if missing from request
        s_params['max_extracted'] = s_params.get('max_extracted', config.submission.default_max_extracted)
        s_params['max_supplementary'] = s_params.get('max_supplementary', config.submission.default_max_supplementary)

        if not Classification.is_accessible(user['classification'], s_params['classification']):
            return make_api_response({}, "You cannot start a scan with higher "
                                     "classification then you're allowed to see", 400)

        # Prepare the output directory
        try:
            os.makedirs(out_dir)
        except Exception:
            pass
        out_file = os.path.join(out_dir, get_random_id())

        # Get the output file
        metadata = flatten(data.get('metadata', {}))
        if not binary:
            if string_type:
                try:
                    found, _, name = fetch_file(string_type, string_value, user, s_params, metadata, out_file,
                                          default_external_sources, name)
                    if not found:
                        raise FileNotFoundError(
                            f"{string_type.upper()} does not exist in Assemblyline or any of the selected sources")

                except FileTooBigException as e:
                    LOGGER.warning(f"[{user['uname']}] {e}")
                    return make_api_response({}, str(e), 400)
                except FileNotFoundError as e:
                    return make_api_response({}, str(e), 404)
                except PermissionError as e:
                    return make_api_response({}, str(e), 400)
            else:
                return make_api_response({}, "Missing file to scan. No binary or fetching method provided.", 400)
        else:
            with open(out_file, "wb") as my_file:
                shutil.copyfileobj(binary, my_file, 16384)

        if not s_params['description']:
            s_params['description'] = default_description

        try:
            # Validate the metadata (use validation scheme if we have one configured for submissions)
            strict = 'submit' in config.submission.metadata.strict_schemes
            metadata_error = metadata_validator.check_metadata(
                metadata, validation_scheme=config.submission.metadata.submit)
            if metadata_error:
                return make_api_response({}, err=metadata_error[1], status_code=400)

            if s_params.get('auto_archive', False):
                # If the submission was set to auto-archive we need to validate the archive metadata fields also
                strict = 'archive' in config.submission.metadata.strict_schemes
                metadata_error = metadata_validator.check_metadata(
                    metadata, validation_scheme=config.submission.metadata.archive,
                    strict=strict, skip_elastic_fields=True)
                if metadata_error:
                    return make_api_response({}, err=metadata_error[1], status_code=400)

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

        try:
            # noinspection PyUnboundLocalVariable
            os.unlink(out_file)
        except Exception:
            pass

        try:
            shutil.rmtree(out_dir, ignore_errors=True)
        except Exception:
            pass
