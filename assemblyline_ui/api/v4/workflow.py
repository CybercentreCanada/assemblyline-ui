
from flask import request

from assemblyline.common.isotime import now_as_iso
from assemblyline.common.uid import get_random_id
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import STORAGE, CLASSIFICATION
from assemblyline.odm.models.workflow import Workflow

SUB_API = 'workflow'
workflow_api = make_subapi_blueprint(SUB_API, api_version=4)
workflow_api._doc = "Manage the different workflows of the system"


# noinspection PyBroadException
def verify_query(query):
    """Ensure that a workflow query can be executed."""
    try:
        STORAGE.alert.search(query, rows=0)
    except Exception:  # If an error occurred in this block we are 100% blaming the user query
        return False
    return True


@workflow_api.route("/", methods=["PUT"])
@api_login(allow_readonly=False)
def add_workflow(**kwargs):
    """
    Add a workflow to the system

    Variables:
    None

    Arguments:
    None

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

    data.update({
        "workflow_id": get_random_id(),
        "creator": kwargs['user']['uname'],
        "edited_by": kwargs['user']['uname'],
        "priority": data['priority'] or None,
        "status": data['status'] or None
    })
    try:
        workflow_data = Workflow(data)
    except ValueError as e:
        return make_api_response({'success': False}, err=str(e), status_code=400)

    return make_api_response({"success": STORAGE.workflow.save(workflow_data.workflow_id, workflow_data),
                              "workflow_id": workflow_data.workflow_id})


@workflow_api.route("/<workflow_id>/", methods=["POST"])
@api_login(allow_readonly=False)
def edit_workflow(workflow_id, **kwargs):
    """
    Edit a workflow.

    Variables:
    workflow_id    => ID of the workflow to edit

    Arguments:
    None

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

    wf = STORAGE.workflow.get(workflow_id, as_obj=False)
    if wf:
        uname = kwargs['user']['uname']
        wf.update(data)
        wf.update({
            "edited_by": uname,
            "last_edit": now_as_iso(),
            "workflow_id": workflow_id
        })

        return make_api_response({"success": STORAGE.workflow.save(workflow_id, wf)})
    else:
        return make_api_response({"success": False},
                                 err="Workflow ID %s does not exist" % workflow_id,
                                 status_code=404)


@workflow_api.route("/<workflow_id>/", methods=["GET"])
@api_login(audit=False, allow_readonly=False, required_priv=['R'])
def get_workflow(workflow_id, **kwargs):
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
    if wf:
        if CLASSIFICATION.is_accessible(kwargs['user']['classification'], wf['classification']):
            return make_api_response(wf)
        else:
            return make_api_response({},
                                     err="You're not allowed to view workflow ID: %s" % workflow_id,
                                     status_code=403)
    else:
        return make_api_response({},
                                 err="Workflow ID %s does not exist" % workflow_id,
                                 status_code=404)


@workflow_api.route("/labels/", methods=["GET"])
@api_login(audit=False, allow_readonly=False, required_priv=['R'])
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
@api_login(audit=False, allow_readonly=False)
def remove_workflow(workflow_id, **_):
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
    wf = STORAGE.workflow.get(workflow_id)
    if wf:
        return make_api_response({"success": STORAGE.workflow.delete(workflow_id)})
    else:
        return make_api_response({"success": False},
                                 err="Workflow ID %s does not exist" % workflow_id,
                                 status_code=404)
