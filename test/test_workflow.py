import json
import pytest
import random

from base import APIError, HOST, login_session, get_api_data

from assemblyline.common import forge
from assemblyline.common.isotime import now_as_iso
from assemblyline.odm.models.workflow import Workflow
from assemblyline.odm.randomizer import random_model_obj
from assemblyline.odm.random_data import create_users, wipe_users, create_services, wipe_services


NUM_WORKFLOWS = 10
ds = forge.get_datastore()
workflow_list = []

def purge_workflow():
    wipe_users(ds)
    wipe_services(ds)
    ds.workflow.wipe()


@pytest.fixture(scope="module")
def datastore(request):
    create_users(ds)
    create_services(ds)

    for x in range(NUM_WORKFLOWS):
        workflow = random_model_obj(Workflow)
        workflow_list.append(workflow.workflow_id)
        ds.workflow.save(workflow.workflow_id, workflow)

    ds.workflow.commit()

    request.addfinalizer(purge_workflow)
    return ds


# noinspection PyUnusedLocal
def test_add_workflow(datastore, login_session):
    _, session = login_session

    workflow = random_model_obj(Workflow).as_primitives()
    workflow['query'] = "sha256:[1 AND 'This is invalid!'"
    workflow['creator'] = 'admin'
    workflow['edited_by'] = 'admin'
    workflow_list.append(workflow['workflow_id'])

    with pytest.raises(APIError):
        resp = get_api_data(session, f"{HOST}/api/v4/workflow/",
                            method="PUT", data=json.dumps(workflow))

    workflow['query'] = "sha256:*"
    resp = get_api_data(session, f"{HOST}/api/v4/workflow/",
                        method="PUT", data=json.dumps(workflow))
    assert resp['success']

    ds.workflow.commit()

    new_workflow = ds.workflow.get(workflow['workflow_id'], as_obj=False)
    assert new_workflow == workflow


# noinspection PyUnusedLocal
def test_get_workflow(datastore, login_session):
    _, session = login_session

    workflow_id = random.choice(workflow_list)

    resp = get_api_data(session, f"{HOST}/api/v4/workflow/{workflow_id}/")
    assert resp == ds.workflow.get(workflow_id, as_obj=False)


# noinspection PyUnusedLocal
def test_list_workflows_labels(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/workflow/labels/")
    assert isinstance(resp, list)
    assert len(resp) > 1

    for x in ds.workflow.search("id:*", fl="labels", as_obj=False)['items']:
        for l in x['labels']:
            assert l in resp


# noinspection PyUnusedLocal
def test_remove_workflow(datastore, login_session):
    _, session = login_session

    workflow_id = random.choice(workflow_list)
    resp = get_api_data(session, f"{HOST}/api/v4/workflow/{workflow_id}/", method="DELETE")
    assert resp['success']

    workflow_list.remove(workflow_id)
    ds.workflow.commit()

    assert ds.workflow.get(workflow_id) is None

# noinspection PyUnusedLocal
def test_set_workflow(datastore, login_session):
    _, session = login_session

    workflow_id = random.choice(workflow_list)
    workflow_data = ds.workflow.get(workflow_id, as_obj=False)
    workflow_data['edited_by'] = 'admin'
    workflow_data['hit_count'] = 111
    workflow_data['last_seen'] = now_as_iso()
    workflow_data['query'] = "query:[1 AND 'THIS IS INVALID'"

    with pytest.raises(APIError):
        resp = get_api_data(session, f"{HOST}/api/v4/workflow/{workflow_id}/",
                            method="POST", data=json.dumps(workflow_data))

    workflow_data['query'] = "file.sha256:12*"
    resp = get_api_data(session, f"{HOST}/api/v4/workflow/{workflow_id}/",
                        method="POST", data=json.dumps(workflow_data))
    assert resp['success']

    ds.workflow.commit()
    new_workflow = ds.workflow.get(workflow_id, as_obj=False)
    new_workflow['last_edit'] = workflow_data['last_edit']
    assert workflow_data == new_workflow
