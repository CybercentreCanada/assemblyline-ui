
from assemblyline.common.archiving import SubmissionNotFound, WebhookFailed, archive_submission as do_archive_submission
from assemblyline.odm.messages.submission import Submission as SubmissionMessage
from assemblyline.odm.models.submission import Submission
from assemblyline.odm.models.user import ROLES
from assemblyline_core.dispatching.schedules import Scheduler
from assemblyline_core.submission_client import SubmissionClient, SubmissionException
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import ARCHIVESTORE, STORAGE, config, CLASSIFICATION as Classification, redis, IDENTIFY, \
    FILESTORE
from assemblyline_ui.helper.submission import submission_received

SUB_API = 'archive'

archive_api = make_subapi_blueprint(SUB_API, api_version=4)
archive_api._doc = "Perform operations on archived submissions"

scheduler = Scheduler(STORAGE, config, redis)


@archive_api.route("/<sid>/", methods=["PUT"])
@api_login(required_priv=['W'], require_role=[ROLES.archive_trigger])
def archive_submission(sid, **kwargs):
    """
    Send a submission to the permanent archive

    Variables:
    sid         => ID of the submission to send to the archive

    Arguments:
    None

    Data Block:
    None

    API call example:
    /api/v4/archive/1234567890/

    Result example:
    {
     "success": True,   # Was the archiving operation successful
     "action": ""       # Which operation took place
    }
    """
    user = kwargs['user']
    submission: Submission = STORAGE.submission.get_if_exists(sid, as_obj=False)
    if not submission:
        return make_api_response({"success": False}, f"The submission '{sid}' was not found in the system", 404)

    if not user or not Classification.is_accessible(user['classification'], submission['classification']):
        return make_api_response({"success": False}, f"The submission '{sid}' is not accessible by this user", 403)

    sub_selected = scheduler.expand_categories(submission['params']['services']['selected'])
    min_selected = scheduler.expand_categories(config.core.archive.minimum_required_services)

    if set(min_selected).issubset(set(sub_selected)):
        try:
            do_archive_submission(sid, STORAGE, FILESTORE, ARCHIVESTORE)
            return make_api_response({"success": True, "action": "archive"})
        except WebhookFailed:
            return make_api_response(
                {"success": False},
                f"The webhook failed before archiving submission '{sid}'", 500)
        except SubmissionNotFound:
            return make_api_response({"success": False}, f"The submission '{sid}' was not found in the system", 404)
        except Exception as e:
            return make_api_response(
                {"success": False},
                f"There were unforseen errors while archiving submission '{sid}' [{e}]", 500)
    else:
        params = submission['params']
        params['auto_archive'] = True
        params['services']['selected'] = list(set(sub_selected).union(set(min_selected)))
        try:
            submission_obj = SubmissionMessage({
                "files": submission["files"],
                "metadata": submission['metadata'],
                "params": params
            })
        except (ValueError, KeyError) as e:
            return make_api_response("", err=str(e), status_code=400)

        try:
            submit_result = SubmissionClient(datastore=STORAGE, filestore=FILESTORE,
                                             config=config, identify=IDENTIFY).submit(submission_obj)

        except SubmissionException as e:
            return make_api_response({"success": False}, err=str(e), status_code=400)
        submission_received(submission_obj)

        return make_api_response({"success": True, "action": "resubmit", "sid": submit_result['sid']})
