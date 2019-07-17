

from al_ui.api.base import api_login, make_subapi_blueprint, make_api_response
from al_ui.config import STORAGE
from assemblyline.common import forge
from assemblyline.odm.models.verdict import ALLOWED_COLLECTION, ALLOWED_VERDICTS

SUB_API = 'verdict'

verdict_api = make_subapi_blueprint(SUB_API, api_version=4)
verdict_api._doc = "Allow the user provide feedback on how accurate is the system"


Classification = forge.get_classification()

@verdict_api.route("/<collection>/<collection_id>/<verdict>/", methods=["PUT"])
@api_login(audit=False, check_xsrf_token=False)
def set_verdict(collection, collection_id, verdict, **kwargs):
    """
    Set the verdict of a document in given collection.

    Variables:
    collection      ->   collection you want to give a verdict for (either 'submission', 'alert', 'result')
    collection_id   ->   ID of the document in the collection to give a verdict to
    verdict         ->   verdict that the document should have been instead of the one reported
                         One of (malicious, highly suspicious, suspicious, non-malicious, safe)

    Arguments:
    None

    Data Block:
    None

    Result example:
    {"success": True}   # Has the verdict been received or not
    """
    collection = collection.lower()
    verdict = verdict.lower()
    if collection not in ALLOWED_COLLECTION:
        return make_api_response({"success": False}, f"Invalid collection name '{collection}'. "
                                                     f"Must be one of: {', '.join(ALLOWED_COLLECTION)}", 400)

    if verdict not in ALLOWED_VERDICTS:
        return make_api_response({"success": False}, f"Invalid verdict '{verdict}'. "
                                                     f"Must be one of: {', '.join(ALLOWED_VERDICTS)}", 400)

    user = kwargs['user']
    c = STORAGE.get_collection(collection)
    document = c.get(collection_id, as_obj=False)

    if not document:
        return make_api_response({"success": False}, f"There are no {collection} with id: {collection_id}", 404)

    if not Classification.is_accessible(user['classification'], document['classification']):
        return make_api_response({"success": False}, f"You are not allowed to give verdict "
                                                     f"on {collection_id} from the {collection} collection", 403)

    key = f"{user['uname']}_{collection}_{collection_id}"
    verdict_doc = {
        "user": user['uname'],
        "date": "NOW",
        "collection": collection,
        "collection_id": collection_id,
        "verdict": verdict
    }
    return make_api_response({"success": STORAGE.verdict.save(key, verdict_doc)})


@verdict_api.route("/<collection>/<collection_id>/")
@api_login(audit=False, check_xsrf_token=False)
def get_verdict(collection, collection_id, **kwargs):
    """
    Get the verdict that you've given to a specific document in a given collection.

    Variables:
    collection      ->   collection you want to get the verdict for (either 'submission', 'alert', 'result')
    collection_id   ->   ID of the document in the collection to get the verdict for

    Arguments:
    None

    Data Block:
    None

    Result example:
    {"success": True}   # Has the verdict been received or not
    """
    collection = collection.lower()
    if collection not in ALLOWED_COLLECTION:
        return make_api_response({"success": False}, f"Invalid collection name '{collection}'. "
        f"Must be one of: {', '.join(ALLOWED_COLLECTION)}", 400)

    user = kwargs['user']
    c = STORAGE.get_collection(collection)
    document = c.get(collection_id, as_obj=False)

    if not document:
        return make_api_response({"success": False}, f"There are no {collection} with id: {collection_id}", 404)

    if not Classification.is_accessible(user['classification'], document['classification']):
        return make_api_response({"success": False}, f"You are not allowed to check verdict "
                                                     f"on {collection_id} from the {collection} collection", 403)

    key = f"{user['uname']}_{collection}_{collection_id}"
    verdict_obj = STORAGE.verdict.get(key, as_obj=False)
    if verdict_obj:
        return make_api_response({"verdict": verdict_obj['verdict'], "date": verdict_obj['date']})
    else:
        return make_api_response({"verdict": None, "date": None})
