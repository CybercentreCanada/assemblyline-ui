
from flask import request

from assemblyline.odm.models.user import ROLES
from assemblyline_core.submission_client import SubmissionException
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import STORAGE, config, CLASSIFICATION as Classification, ARCHIVE_MANAGER

SUB_API = 'archive'

archive_api = make_subapi_blueprint(SUB_API, api_version=4)
archive_api._doc = "Perform operations on archived submissions"


@archive_api.route("/<sid>/", methods=["PUT"])
@api_login(require_role=[ROLES.archive_trigger])
def archive_submission(sid, **kwargs):
    """
    Send a submission to the permanent archive

    Variables:
    sid         => ID of the submission to send to the archive

    Arguments:
    delete_after     => Delete data from hot storage after the move ? (Default: False)

    Data Block:
    None

    API call example:
    /api/v4/archive/12345...67890/

    Result example:
    {
     "success": True,      # Was the archiving operation successful
     "action": "archive",  # Which operation took place (archive or resubmit)
     "sid": None           # (Optional) Submission ID of the new submission with extended
                           #            service selection
    }
    """
    if not config.datastore.archive.enabled:
        return make_api_response({"success": False}, "Archiving is disabled on the server.", 403)

    user = kwargs['user']
    delete_after = request.args.get('delete_after', 'false').lower() in ['true', '']
    submission = STORAGE.submission.get_if_exists(sid, as_obj=False)
    if not submission:
        return make_api_response({"success": False}, f"The submission '{sid}' was not found in the system", 404)

    if not user or not Classification.is_accessible(user['classification'], submission['classification']):
        return make_api_response({"success": False}, f"The submission '{sid}' is not accessible by this user", 403)

    try:
        archive_action = ARCHIVE_MANAGER.archive_submission(submission=submission, delete_after=delete_after)
        archive_action['success'] = True
        return make_api_response(archive_action)

    except SubmissionException as se:
        return make_api_response({"success": False}, err=str(se), status_code=400)
