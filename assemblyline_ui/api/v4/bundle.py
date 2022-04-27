import base64
import binascii
import os

from cart import is_cart
from flask import request

from assemblyline.common.bundling import create_bundle as bundle_create, import_bundle as bundle_import,\
    SubmissionNotFound, BundlingException, SubmissionAlreadyExist, IncompleteBundle, BUNDLE_MAGIC
from assemblyline.common.classification import InvalidClassification
from assemblyline.common.uid import get_random_id
from assemblyline_core.submission_client import SubmissionException
from assemblyline_ui.api.base import api_login, make_api_response, stream_file_response, make_subapi_blueprint
from assemblyline_ui.config import BUNDLING_DIR, CLASSIFICATION as Classification, STORAGE


SUB_API = 'bundle'

bundle_api = make_subapi_blueprint(SUB_API, api_version=4)
bundle_api._doc = "Create and restore submission bundles"


# noinspection PyBroadException
@bundle_api.route("/<sid>/", methods=["GET"])
@api_login(required_priv=['R'])
def create_bundle(sid, **kwargs):
    """
    Creates a bundle containing the submission results and the associated files

    Variables:
    sid         => ID of the submission to create the bundle for

    Arguments:
    use_alert   => The ID provided is from an alert and we will use it to create the bundle

    Data Block:
    None

    API call example:
    /api/v4/bundle/create/234f334-...-31232/

    Result example:
    -- THE BUNDLE FILE BINARY --
    """
    user = kwargs['user']
    use_alert = request.args.get('use_alert', 'false').lower() in ['true', '']
    if use_alert:
        data = STORAGE.alert.get(sid, as_obj=False)
    else:
        data = STORAGE.submission.get(sid, as_obj=False)

    if user and data and Classification.is_accessible(user['classification'], data['classification']):
        temp_target_file = None
        try:
            temp_target_file = bundle_create(sid, working_dir=BUNDLING_DIR, use_alert=use_alert)
            f_size = os.path.getsize(temp_target_file)
            return stream_file_response(open(temp_target_file, 'rb'), "%s.al_bundle" % sid, f_size)
        except SubmissionNotFound as snf:
            return make_api_response("", "Submission %s does not exist. [%s]" % (sid, str(snf)), 404)
        except BundlingException as be:
            return make_api_response("",
                                     "An error occured while bundling submission %s. [%s]" % (sid, str(be)),
                                     404)
        finally:
            try:
                if temp_target_file:
                    os.remove(temp_target_file)
            except Exception:
                pass
    else:
        return make_api_response(
            "", f"You are not allowed create a bundle for this {'alert' if use_alert else 'submission'}...", 403)


@bundle_api.route("/", methods=["POST"])
@api_login(required_priv=['W'], allow_readonly=False)
def import_bundle(**_):
    """
    Import a bundle file into the system

    Variables:
    None

    Arguments:
    allow_incomplete        => allow importing incomplete submission
    rescan_services         => Comma seperated list of services to rescan after importing the bundle
    min_classification      => Minimum classification that the files and result from the bundle should get
    exist_ok                => Does not fail if submission already exists

    Data Block:
    The bundle file to import

    Result example:
    {"success": true}
    """
    allow_incomplete = request.args.get('allow_incomplete', 'false').lower() in ['true', '']
    exist_ok = request.args.get('exist_ok', 'false').lower() in ['true', '']
    min_classification = request.args.get('min_classification', Classification.UNRESTRICTED)
    rescan_services = request.args.get('rescan_services', None)

    if rescan_services is not None:
        rescan_services = rescan_services.split(',')

    current_bundle = os.path.join(BUNDLING_DIR, f"{get_random_id()}.bundle")

    with open(current_bundle, 'wb') as fh:
        if request.data[:3] == BUNDLE_MAGIC or is_cart(request.data[:256]):
            fh.write(request.data)
        else:
            try:
                fh.write(base64.b64decode(request.data))
            except binascii.Error:
                fh.write(request.data)

    try:
        bundle_import(current_bundle, working_dir=BUNDLING_DIR, min_classification=min_classification,
                      allow_incomplete=allow_incomplete, rescan_services=rescan_services, exist_ok=exist_ok)

        return make_api_response({'success': True})
    except SubmissionException as se:
        return make_api_response({'success': False}, err=str(se), status_code=409)
    except InvalidClassification as ice:
        return make_api_response({'success': False}, err=str(ice), status_code=400)
    except SubmissionAlreadyExist as sae:
        return make_api_response({'success': False}, err=str(sae), status_code=409)
    except (IncompleteBundle, BundlingException) as b:
        return make_api_response({'success': False}, err=str(b), status_code=400)
