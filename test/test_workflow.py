import json
import pytest
import random

from conftest import APIError, get_api_data

from assemblyline.common.isotime import now_as_iso
from assemblyline.odm.models.workflow import Workflow
from assemblyline.odm.randomizer import random_model_obj
from assemblyline.odm.random_data import create_users, wipe_users, create_services, wipe_services


NUM_WORKFLOWS = 10
workflow_list = []


@pytest.fixture(scope="module")
def datastore(datastore_connection):
    try:
        create_users(datastore_connection)
        create_services(datastore_connection)

        for _ in range(NUM_WORKFLOWS):
            workflow = random_model_obj(Workflow)
            workflow_list.append(workflow.workflow_id)
            datastore_connection.workflow.save(workflow.workflow_id, workflow)

        datastore_connection.workflow.commit()
        yield datastore_connection
    finally:
        wipe_users(datastore_connection)
        wipe_services(datastore_connection)
        datastore_connection.workflow.wipe()


# noinspection PyUnusedLocal
def test_add_workflow(datastore, login_session):
    _, session, host = login_session

    workflow = random_model_obj(Workflow).as_primitives()
    workflow['query'] = "sha256:[1 AND 'This is invalid!'"
    workflow['creator'] = 'admin'
    workflow['edited_by'] = 'admin'

    with pytest.raises(APIError):
        resp = get_api_data(session, f"{host}/api/v4/workflow/",
                            method="PUT", data=json.dumps(workflow))

    workflow['query'] = "sha256:*"
    resp = get_api_data(session, f"{host}/api/v4/workflow/",
                        method="PUT", data=json.dumps(workflow))
    assert resp['success']
    workflow['workflow_id'] = resp['workflow_id']
    workflow_list.append(resp['workflow_id'])

    datastore.workflow.commit()

    new_workflow = datastore.workflow.get(resp['workflow_id'], as_obj=False)
    assert new_workflow == workflow


# noinspection PyUnusedLocal
def test_get_workflow(datastore, login_session):
    _, session, host = login_session

    workflow_id = random.choice(workflow_list)

    resp = get_api_data(session, f"{host}/api/v4/workflow/{workflow_id}/")
    assert resp == datastore.workflow.get(workflow_id, as_obj=False)


# noinspection PyUnusedLocal
def test_list_workflows_labels(datastore, login_session):
    _, session, host = login_session

    resp = get_api_data(session, f"{host}/api/v4/workflow/labels/")
    assert isinstance(resp, list)
    assert len(resp) > 1

    for x in datastore.workflow.search("id:*", fl="labels", as_obj=False)['items']:
        for label in x['labels']:
            assert label in resp


# noinspection PyUnusedLocal
def test_remove_workflow(datastore, login_session):
    _, session, host = login_session

    workflow_id = random.choice(workflow_list)
    resp = get_api_data(session, f"{host}/api/v4/workflow/{workflow_id}/", method="DELETE")
    assert resp['success']

    workflow_list.remove(workflow_id)
    datastore.workflow.commit()

    assert datastore.workflow.get(workflow_id) is None


# noinspection PyUnusedLocal
def test_set_workflow(datastore, login_session):
    _, session, host = login_session

    workflow_id = random.choice(workflow_list)
    workflow_data = datastore.workflow.get(workflow_id, as_obj=False)
    workflow_data['edited_by'] = 'admin'
    workflow_data['hit_count'] = 111
    workflow_data['last_seen'] = now_as_iso()
    workflow_data['query'] = "query:[1 AND 'THIS IS INVALID'"

    with pytest.raises(APIError):
        resp = get_api_data(session, f"{host}/api/v4/workflow/{workflow_id}/",
                            method="POST", data=json.dumps(workflow_data))

    workflow_data['query'] = "file.sha256:12*"
    resp = get_api_data(session, f"{host}/api/v4/workflow/{workflow_id}/",
                        method="POST", data=json.dumps(workflow_data))
    assert resp['success']

    datastore.workflow.commit()
    new_workflow = datastore.workflow.get(workflow_id, as_obj=False)
    new_workflow['last_edit'] = workflow_data['last_edit']
    assert workflow_data == new_workflow
