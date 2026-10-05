
from flask import request

from assemblyline.common.isotime import now_as_iso
from assemblyline.common.uid import get_random_id
from assemblyline.odm.models.user import ROLES
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import STORAGE, CLASSIFICATION, config
from assemblyline.odm.models.alert import Event
from assemblyline.odm.models.workflow import Workflow

SUB_API = 'workflow'
workflow_api = make_subapi_blueprint(SUB_API, api_version=4)
workflow_api._doc = "Manage the different workflows of the system"


def get_alert_update_ops(workflow: Workflow):
    operations = []
    if workflow.status:
        operations.append((STORAGE.alert.UPDATE_SET, 'status', workflow.status))
    if workflow.priority:
        operations.append((STORAGE.alert.UPDATE_SET, 'priority', workflow.priority))
    for label in workflow.labels:
        operations.append((STORAGE.alert.UPDATE_APPEND_IF_MISSING, 'label', label))

    if operations:
        # Make sure operations get audited
        operations.append((STORAGE.alert.UPDATE_APPEND,
                           'events',
                           Event({
                               "entity_type": "workflow",
                               "entity_id": workflow.workflow_id,
                               "entity_name": workflow.name,
                               "priority": workflow.priority,
                               "status": workflow.status,
                               "labels": workflow.labels or None,
                           })
                           ))

    return operations


# noinspection PyBroadException
def verify_query(query):
    """Ensure that a workflow query can be executed."""
    try:
        STORAGE.alert.search(query, rows=0)
    except Exception:  # If an error occurred in this block we are 100% blaming the user query
        return False
    return True


def workflow_does_not_exist(workflow_id):
    """Create an api response for when we want to report a workflow as not existing."""
    return make_api_response({"success": False},
                             err=f"Workflow ID {workflow_id} does not exist",
                             status_code=404)


@workflow_api.route("/", methods=["PUT"])
@api_login(allow_readonly=False, require_role=[ROLES.workflow_manage])
def add_workflow(user, **_):
    """
    Add a workflow to the system

    Variables:
    None

    Arguments:
    run_workflow      => Run workflow immediately on past alerts

    Data Block:
    {
     "name": "Workflow name",    # Name of the workflow
     "classification": "",       # Max classification for workflow
     "label": ['label1'],        # Labels for the workflow
     "priority": "LOW",          # Priority of the workflow
     "status": "MALICIOUS",      # Status of the workflow
     "query": "*:*"              # Query to match the data
    }

    Result example:
    {
     "success": true             # Saving the user info succeded
    }
    """

    data = request.json

    name = data.get('name', None)
    query = data.get('query', None)

    if not name:
        return make_api_response({"success": False}, err="Name field is required", status_code=400)

    if not query:
        return make_api_response({"success": False}, err="Query field is required", status_code=400)

    if not verify_query(query):
        return make_api_response({"success": False}, err="Query contains an error", status_code=400)

    # Check that users are only creating workflows they can themselves see, if not set it will be UNRESTRICTED
    if 'classification' in data:
        if not CLASSIFICATION.is_accessible(user['classification'], data['classification']):
            return make_api_response({"success": False}, err="Verify classification field", status_code=400)

    data.update({
        "workflow_id": get_random_id(),
        "creator": user['uname'],
        "edited_by": user['uname'],
        "priority": data['priority'] or None,
        "status": data['status'] or None,
        "origin": data.get('origin') or config.ui.fqdn
    })
    try:
        workflow_data = Workflow(data)
    except ValueError as e:
        return make_api_response({'success': False}, err=str(e), status_code=400)

    success = STORAGE.workflow.save(workflow_data.workflow_id, workflow_data)

    run_workflow = request.args.get('run_workflow', 'false').lower() == 'true'
    if success and run_workflow:
        # Process workflow against all alerts in the system matching the query
        STORAGE.alert.update_by_query(query=workflow_data.query, operations=get_alert_update_ops(workflow_data))

    return make_api_response({"success": success,
                              "workflow_id": workflow_data.workflow_id})


@workflow_api.route("/<workflow_id>/", methods=["POST"])
@api_login(allow_readonly=False, require_role=[ROLES.workflow_manage])
def edit_workflow(workflow_id, user, **_):
    """
    Edit a workflow.

    Variables:
    workflow_id         => ID of the workflow to edit

    Data Block:
    {
     "name": "Workflow name",    # Name of the workflow
     "classification": "",       # Max classification for workflow
     "label": ['label1'],        # Labels for the workflow
     "priority": "LOW",          # Priority of the workflow
     "status": "MALICIOUS",      # Status of the workflow
     "query": "*:*"              # Query to match the data
    }

    Result example:
    {
     "success": true             # Saving the user info succeded
    }
    """
    data = request.json
    name = data.get('name', None)
    query = data.get('query', None)

    if not name:
        return make_api_response({"success": False}, err="Name field is required", status_code=400)

    if not query:
        return make_api_response({"success": False}, err="Query field is required", status_code=400)

    if not verify_query(query):
        return make_api_response({"success": False}, err="Query contains an error", status_code=400)

    if 'classification' in data:
        if not CLASSIFICATION.is_accessible(user['classification'], data['classification']):
            return make_api_response({"success": False}, err="Verify classification field", status_code=400)

    wf = STORAGE.workflow.get(workflow_id, as_obj=False)
    if not wf or not CLASSIFICATION.is_accessible(user['classification'], wf['classification']):
        return workflow_does_not_exist(workflow_id)

    wf.update(data)
    wf.update({
        "edited_by": user['uname'],
        "last_edit": now_as_iso(),
        "workflow_id": workflow_id
    })

    success = STORAGE.workflow.save(workflow_id, wf)
    return make_api_response({"success": success})


@workflow_api.route("/enable/<workflow_id>/", methods=["PUT"])
@api_login(allow_readonly=False, require_role=[ROLES.workflow_manage])
def set_workflow_status(workflow_id, user, **_):
    """
    Set the enabled status of a workflow

    Variables:
    workflow_id       => ID of the workflow

    Arguments:
    None

    Data Block:
    {
     "enabled": "true"              # Enable or disable the workflow
    }

    Result example:
    {"success": True}
    """
    data = request.json
    enabled = data.get('enabled', None)

    if enabled is None:
        return make_api_response({"success": False}, err="Enabled field is required", status_code=400)

    wf = STORAGE.workflow.get(workflow_id, as_obj=False)
    if not wf or not CLASSIFICATION.is_accessible(user['classification'], wf['classification']):
        return workflow_does_not_exist(workflow_id)

    return make_api_response({'success': STORAGE.workflow.update(
        workflow_id, [
            (STORAGE.workflow.UPDATE_SET, 'enabled', enabled),
            (STORAGE.workflow.UPDATE_SET, 'last_edit', now_as_iso()),
        ]
    )})


@workflow_api.route("/<workflow_id>/", methods=["GET"])
@api_login(audit=False, allow_readonly=False, require_role=[ROLES.workflow_view])
def get_workflow(workflow_id, user, **_):
    """
    Load the user account information.

    Variables:
    workflow_id       => ID of the workflow

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
     "name": "Workflow name",    # Name of the workflow
     "classification": "",       # Max classification for workflow
     "label": ['label1'],        # Labels for the workflow
     "priority": "LOW",          # Priority of the workflow
     "status": "MALICIOUS",      # Status of the workflow
     "query": "*:*"              # Query to match the data
    }
    """
    wf = STORAGE.workflow.get(workflow_id, as_obj=False)
    if not wf or not CLASSIFICATION.is_accessible(user['classification'], wf['classification']):
        return workflow_does_not_exist(workflow_id)

    wf['origin'] = wf.get('origin', config.ui.fqdn)
    return make_api_response(wf)


@workflow_api.route("/labels/", methods=["GET"])
@api_login(audit=False, allow_readonly=False, require_role=[ROLES.workflow_view])
def list_workflow_labels(**kwargs):
    """
    List all labels from the workflows

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    [
      "LABEL1",
      "LABEL2"
      ...
    ]
    """
    access_control = kwargs['user']['access_control']
    return make_api_response(list(STORAGE.workflow.facet("labels", access_control=access_control).keys()))


@workflow_api.route("/<workflow_id>/", methods=["DELETE"])
@api_login(audit=False, allow_readonly=False, require_role=[ROLES.workflow_manage])
def remove_workflow(workflow_id, user, **_):
    """
    Remove the specified workflow.

    Variables:
    workflow_id       => ID of the workflow to remove

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
     "success": true  # Was the remove successful?
    }
    """
    wf: Workflow = STORAGE.workflow.get(workflow_id)
    if not wf or not CLASSIFICATION.is_accessible(user['classification'], wf.classification.value):
        return workflow_does_not_exist(workflow_id)

    return make_api_response({"success": STORAGE.workflow.delete(workflow_id)})


@workflow_api.route("/<workflow_id>/run/", methods=["GET"])
@api_login(audit=False, allow_readonly=False, require_role=[ROLES.workflow_manage])
def run_workflow(workflow_id, user, **_):
    """
    Run the specified workflow against all existing alerts that match the query

    Variables:
    workflow_id       => ID of the workflow to run

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
     "success": true  # Was the run successful?
    }
    """
    wf: Workflow = STORAGE.workflow.get(workflow_id)
    if not wf or not CLASSIFICATION.is_accessible(user['classification'], wf.classification.value):
        return workflow_does_not_exist(workflow_id)

    # Process workflow against all alerts in the system matching the query
    ret_value = STORAGE.alert.update_by_query(query=wf.query, operations=get_alert_update_ops(wf))
    return make_api_response({"success": ret_value is not False})
