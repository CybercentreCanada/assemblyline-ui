from flask import request

from assemblyline.common.isotime import now_as_iso
from assemblyline.common.uid import get_random_id
from assemblyline.datastore.collection import Index
from assemblyline.datastore.exceptions import DataStoreException, VersionConflictException
from assemblyline.odm.models.file import REACTIONS_TYPES
from assemblyline.odm.models.user import ROLES
from assemblyline.remote.datatypes.queues.comms import CommsQueue
from assemblyline_core.submission_client import SubmissionException
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import LOGGER, STORAGE, config, CLASSIFICATION as Classification, ARCHIVE_MANAGER

SUB_API = 'archive'
LABEL_CATEGORIES = ['attribution', 'technique', 'info']

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


@archive_api.route("/details/<sha256>/", methods=["GET", "POST"])
@api_login(require_role=[ROLES.submission_view])
def get_additional_details(sha256, **kwargs):
    """
    Get additional details in the archive file details

    Variables:
    sha256                  => A resource locator for the file (SHA256)

    Arguments:
    offset                  => Offset at which we start giving files
    rows                    => Numbers of files to return
    sort                    => How to sort the results (not available in deep paging)

    Data Block:
    {
        "offset": 0,        # Offset in the results
        "rows": 100,        # Max number of results
        "sort": "field asc",# How to sort the results
    }

    API call example:
    /api/v4/file/result/123456...654321/

    Result example:
    {
        "tlsh": {           # List of files related by their tlsh
            "items": []     # List of files hash
            "count": 100,   # Number of files returned
            "offset": 0,    # Offset in the file list
            "total": 201,   # Total files found
        },
        "ssdeep1": {...},   # List of files related by the first part of their ssdeep
        "ssdeep2": {...},   # List of files related by the second part of their ssdeep
        "vector": {...}     # List of files related by their vector
    }
    """
    user = kwargs['user']
    file_obj = STORAGE.file.get_if_exists(sha256, as_obj=False)

    if not file_obj:
        return make_api_response({"success": False}, "This file does not exists", 404)

    if not user or not Classification.is_accessible(user['classification'], file_obj['classification']):
        return make_api_response({"success": False}, "You are not allowed to view this file", 403)

    # Set the default search parameters
    params = {}
    params.setdefault('offset', 0)
    params.setdefault('rows', 10)
    params.setdefault('sort', 'seen.last desc')
    params.setdefault('fl', 'type,sha256,seen.last')
    params.setdefault('filters', [f'NOT(sha256:"{sha256}")'])
    params.setdefault('access_control', user['access_control'])
    params.setdefault('as_obj', False)
    params.setdefault('index_type', Index.HOT_AND_ARCHIVE)

    fields = ["offset", "rows", "sort"]

    req_data = None
    if request.method == "POST":
        req_data = request.json
    else:
        req_data = request.args

    params.update({k: req_data.get(k, None) for k in fields if req_data.get(k, None) is not None})

    output = {'tlsh': {}, 'ssdeep1': {}, 'ssdeep2': {}, 'vector': {}}

    # Process tlsh
    try:
        tlsh = file_obj['tlsh'].replace('/', '\\/')
        output['tlsh'] = STORAGE.file.search(query=f"tlsh:{tlsh}", **params)
    except Exception as e:
        output['tlsh'] = f"SearchException: {e}"

    # Process ssdeep
    try:
        ssdeep = file_obj.get('ssdeep', '').replace('/', '\\/').split(':')
        output['ssdeep1'] = STORAGE.file.search(query=f"ssdeep:{ssdeep[1]}~", **params)
        output['ssdeep2'] = STORAGE.file.search(query=f"ssdeep:{ssdeep[2]}~", **params)
    except Exception as e:
        output['ssdeep1'] = f"SearchException: {e}"
        output['ssdeep2'] = f"SearchException: {e}"

    # Process vector
    try:
        results = STORAGE.result.search(
            f"sha256:{sha256} AND response.service_name:APIVector", sort="created desc", as_obj=False)
        results = STORAGE.result.multiget(
            [result['id'] for result in results.get('items', None)],
            as_dictionary=False, as_obj=False)

        vector = []
        for result in results:
            for section in result['result']['sections']:
                vector.extend(section['tags']['vector'])

        query = ' OR '.join([f"result.sections.tags.vector:{v}" for v in vector])
        results = STORAGE.result.search(query=query, as_obj=False)
        ids = set([x['id'].split('.')[0] for x in STORAGE.result.stream_search(query=query, fl="id", as_obj=False)])
        query = ' OR '.join(f"sha256:{id}" for id in ids)
        output['vector'] = STORAGE.file.search(query=query, **params)
    except Exception as e:
        output['vector'] = f"SearchException: {e}"

    return make_api_response(output)


@archive_api.route("/comment/<sha256>/", methods=["GET"])
@api_login(require_role=[ROLES.file_detail], allow_readonly=False)
def get_comments(sha256, **kwargs):
    """
    Get all comments with their author made on a given file

    Variables:
    sha256          => A resource locator for the file (sha256)

    Arguments:
    None

    Data Block:
    None

    API call example:
    /api/v4/file/comment/123456...654321/

    Result example:
    {
        authors: {
            <uname>: {
                "uname":    "admin",
                "name":     "Administrator",
                "avatar":   "data:image/png;base64,123...321",
                "email":    "admin@assemblyline.cyber.gc.ca"
            }
        },
        comments: [{
            "cid":      "123...321",
            "uname"     "admin",
            "date":     "2023-01-01T12:00:00.000000",
            "text":     "This is a new comment"
        }]
    }
    """
    file_obj = STORAGE.file.get_if_exists(sha256, as_obj=False, index_type=Index.ARCHIVE)
    if not file_obj:
        return make_api_response({"success": False}, "The file was not found in the system.", 404)

    user = kwargs['user']
    if not Classification.is_accessible(user['classification'], file_obj['classification']):
        return make_api_response({"success": False}, "You are not allowed to make a reaction to this file...", 403)

    try:
        comments = file_obj.get("comments", {})
        authors = {}
        authors.update({comment.get('uname', None): {} for comment in comments})
        authors.update({reaction.get('uname', None): {} for comment in comments
                        for reaction in comment.get('reactions', []) if reaction.get('uname', None) is not None})

        for author in authors:
            user = STORAGE.user.get_if_exists(author, as_obj=False)
            if user is None:
                authors[author] = None
            else:
                authors[author].update({
                    "uname": user.get('uname', None),
                    "name": user.get('name', None),
                    "email": user.get('email', None)
                })
                avatar = STORAGE.user_avatar.get_if_exists(author, as_obj=False)
                if avatar is not None:
                    authors[author].update({"avatar": avatar})

        authors = {author: authors[author] for author in authors if authors[author] is not None}
        return make_api_response({"authors": authors, "comments": comments})
    except (ValueError, DataStoreException) as e:
        return make_api_response({"success": False}, err=str(e), status_code=400)


@archive_api.route("/comment/<sha256>/", methods=["PUT"])
@api_login(require_role=[ROLES.file_detail], allow_readonly=False)
def add_comment(sha256, **kwargs):
    """
    Add a comment to a given file

    Variables:
    sha256          => A resource locator for the file (sha256)

    Arguments:
    None

    Data Block:     => Text of the new comment being made
    {
        "text": "This is a new comment"
    }

    API call example:
    /api/v4/file/comment/123456...654321/

    Result example:
    {
        "cid":      "123...321"
        "uname":    "admin",
        "date":     "2023-01-01T12:00:00.000000",
        "text":     "This is a new comment"
    }
    """
    data = request.json
    user = kwargs['user']

    # Get the comment from the data block
    text = data.get('text', None)
    if not isinstance(text, str):
        return make_api_response({"success": False}, err="Invalid text property", status_code=400)

    # Create the new comment
    new_comment = {
        'cid': get_random_id(),
        'date': now_as_iso(),
        'text': text,
        'uname': user['uname'],
        'reactions': []
    }

    while True:
        # Get the current file data
        file_obj, version = STORAGE.file.get_if_exists(sha256, as_obj=False, version=True, index_type=Index.ARCHIVE)
        if not file_obj:
            return make_api_response({"success": False}, "The file was not found in the system.", 404)

        if not Classification.is_accessible(user['classification'], file_obj['classification']):
            return make_api_response({"success": False}, "You are not allowed to add a comment to this file...", 403)

        # Add the comment to the file
        try:
            file_obj.setdefault('comments', [])
            file_obj['comments'].insert(0, new_comment)
            STORAGE.file.save(sha256, file_obj, version=version, index_type=Index.ARCHIVE)
            break
        except VersionConflictException as vce:
            LOGGER.info(f"Retrying saving comment due to version conflict: {str(vce)}")

    q = CommsQueue('file_comments', private=True)
    q.publish({'sha256': sha256})
    return make_api_response(new_comment)


@archive_api.route("/comment/<sha256>/<cid>/", methods=["POST"])
@api_login(require_role=[ROLES.file_detail], allow_readonly=False)
def update_comment(sha256, cid, **kwargs):
    """
    Update the comment <cid> in a given file

    Variables:
    sha256          => A resource locator for the file (sha256)
    cid             => ID of the comment

    Arguments:
    None

    Data Block:     => Text of the comment to update
    {
        "text": "This is a new comment"
    }

    API call example:
    /api/v4/file/comment/123456...654321/123...321/

    Result example: => Comment has been successfully updated
    {
        "success": True
    }
    """
    data = request.json

    text = data.get('text', None)
    if not isinstance(text, str):
        return make_api_response({"success": False}, err="Invalid text property", status_code=400)

    while True:
        try:
            file_obj, version = STORAGE.file.get_if_exists(sha256, as_obj=False, version=True, index_type=Index.ARCHIVE)
            if not file_obj:
                return make_api_response({"success": False}, "The file was not found in the system.", 404)

            user = kwargs['user']
            if not Classification.is_accessible(user['classification'], file_obj['classification']):
                return make_api_response(
                    {"success": False},
                    "You are not allowed to modify a comment on this file...", 403)

            file_obj.setdefault('comments', [])
            index = next((i for i, c in enumerate(file_obj['comments']) if c.get('cid', None) == cid), None)
            if index is None:
                return make_api_response(
                    {"success": False},
                    f"No comment with an id of \"{cid}\" was found in this file", status_code=404)

            if (file_obj['comments'][index]['uname'] != user['uname']):
                return make_api_response({"success": False}, "Another user's comment cannot be updated.", 403)

            file_obj['comments'][index].update({'text': text})
            STORAGE.file.save(sha256, file_obj, version=version, index_type=Index.ARCHIVE)
            break
        except VersionConflictException as vce:
            LOGGER.info(f"Retrying saving comment due to version conflict: {str(vce)}")

        except DataStoreException as e:
            return make_api_response({"success": False}, err=str(e), status_code=400)

    q = CommsQueue('file_comments', private=True)
    q.publish({'sha256': sha256})
    return make_api_response({"success": True})


@archive_api.route("/comment/<sha256>/<cid>/", methods=["DELETE"])
@api_login(require_role=[ROLES.file_detail])
def delete_comment(sha256, cid, **kwargs):
    """
    Delete the comment <cid> in a given file

    Variables:
    sha256          => A resource locator for the file (sha256)
    cid             => ID of the comment

    Arguments:
    None

    Data Block:
    None

    API call example:
    /api/v4/file/comment/123456...654321/123...321/

    Result example: => Comment has been successfully deleted
    {
        "success": True
    }
    """
    data = request.json

    text = data.get('text', None)
    if not isinstance(text, str):
        return make_api_response({"success": False}, err="Invalid text property", status_code=400)

    while True:
        try:
            file_obj, version = STORAGE.file.get_if_exists(sha256, as_obj=False, version=True, index_type=Index.ARCHIVE)
            if not file_obj:
                return make_api_response({"success": False}, "The file was not found in the system.", 404)

            user = kwargs['user']
            if not Classification.is_accessible(user['classification'], file_obj['classification']):
                return make_api_response(
                    {"success": False},
                    "You are not allowed to modify a comment on this file...", 403)

            file_obj.setdefault('comments', [])
            index = next((i for i, c in enumerate(file_obj['comments']) if c.get('cid', None) == cid), None)
            if index is None:
                return make_api_response({"success": False}, "The comment was not found within the file.", 404)

            if (file_obj['comments'][index]['uname'] != user['uname']):
                return make_api_response({"success": False}, "Another user's comment cannot be deleted.", 403)

            file_obj['comments'].pop(index)
            STORAGE.file.save(sha256, file_obj, version=version, index_type=Index.ARCHIVE)
            break
        except VersionConflictException as vce:
            LOGGER.info(f"Retrying saving comment due to version conflict: {str(vce)}")

        except DataStoreException as e:
            return make_api_response({"success": False}, err=str(e), status_code=400)

    q = CommsQueue('file_comments', private=True)
    q.publish({'sha256': sha256})
    return make_api_response({"success": True})


@archive_api.route("/reaction/<sha256>/<cid>/<icon>/", methods=["PUT"])
@api_login(allow_readonly=False, require_role=[ROLES.file_detail])
def toggle_reaction(sha256, cid, icon, **kwargs):
    """
    Add or remove a reaction made on a comment to a given file

    Variables:
    sha256      => A resource locator for the file (sha256)
    cid         => A resource locator for the comment (cid)
    icon        => Type of reaction made (icon)

    Arguments:
    None

    Data Block:
    None

    API call example:
    /api/v4/file/reaction/123456...654321/123456...654321/like/

    Result example:
    [
        {
            "uname":    "admin",
            "icon":     "thumbs_up"
        },
        {
            ...
        }
    ]
    """
    while True:
        try:
            if icon not in REACTIONS_TYPES:
                return make_api_response({"success": False}, err="Invalid text property", status_code=400)

            file_obj, version = STORAGE.file.get_if_exists(sha256, as_obj=False, version=True, index_type=Index.ARCHIVE)
            if not file_obj:
                return make_api_response({"success": False}, "The file was not found in the system.", status_code=404)

            user = kwargs['user']
            if not Classification.is_accessible(user['classification'], file_obj['classification']):
                return make_api_response("", "You are not allowed to make a reaction to this file...", 403)

            file_obj.setdefault('comments', [])
            c_index = next((i for i, c in enumerate(file_obj['comments']) if c.get('cid', None) == cid), None)
            if c_index is None:
                return make_api_response(
                    {"success": False},
                    f"No comment with an id of \"{cid}\" was found in this file", status_code=404)

            r_index = next((i for i, r in enumerate(file_obj['comments'][c_index]['reactions']) if r.get(
                'uname', None) == user['uname'] and r.get('icon', None) == icon), None)

            if r_index is None:
                file_obj['comments'][c_index]['reactions'].append({'uname': user['uname'], 'icon': icon})
            else:
                file_obj['comments'][c_index]['reactions'].pop(r_index)

            STORAGE.file.save(sha256, file_obj, version=version, index_type=Index.ARCHIVE)
            break
        except VersionConflictException as vce:
            LOGGER.info(f"Retrying saving reactions due to version conflict: {str(vce)}")

        except DataStoreException as e:
            return make_api_response({"success": False}, err=str(e), status_code=400)

    q = CommsQueue('file_comments', private=True)
    q.publish({'sha256': sha256})
    return make_api_response(file_obj['comments'][c_index]['reactions'])


@archive_api.route("/label/", methods=["GET", "POST"])
@api_login(allow_readonly=False, require_role=[ROLES.file_detail])
def get_label_suggestions(**kwargs):
    """
    Get the suggestions based on the labels of all the files

    Optional Arguments:
    include         =>  Input value of the label to search for
    query           =>  Query to filter the searched documents
    mincount        =>  Minimum item count for the fieldvalue to be returned
    filters         =>  Additional query to limit to output
    size            =>  Maximum number of items returned

    Data Block (POST ONLY):
    {
        "include": "label",
        "query": "*",
        "mincount": 1,
        "filters": ['fq'],
        "size": 10
    }

    Result example:
    [
        {
            "category": "attribution",
            "label": "test label",
            "total": 0
        },
        {...}
    ]
    """
    user = kwargs['user']
    fields = ["query", "mincount", "size"]
    params = {}
    filters = []

    if request.method == "POST":
        req_data = request.json
        if req_data.get('filters', None):
            filters.append(req_data.get('filters', None))
    else:
        req_data = request.args
        if req_data.getlist('filters', None):
            filters.append(req_data.getlist('filters', None))

    params.update({k: req_data.get(k, None) for k in fields if req_data.get(k, None) is not None})
    params.update({'field': [f"label_categories.{category}" for category in LABEL_CATEGORIES]})
    params.update({'include': f".*{req_data.get('include', '')}.*" if req_data.get('include', None) else None})
    params.update({'filters': filters})
    params.update({'access_control': user['access_control']})
    params.update({'index_type': Index.ARCHIVE})

    try:
        result = STORAGE.file.facet(**params)
        result = [{"category": category, "label": b, "count": c}
                  for category in LABEL_CATEGORIES for b, c in result[f"label_categories.{category}"].items()]
        result.sort(key=lambda value: value['count'], reverse=True)
        return make_api_response(result[0:req_data.get('count', 10)])
    except ValueError:
        return make_api_response({"success": False}, err="Error fetching the list of labels.", status_code=400)


@archive_api.route("/label/<sha256>/", methods=["POST"])
@api_login(allow_readonly=False, require_role=[ROLES.file_detail])
def set_labels(sha256, **kwargs):
    """
    Set the labels of a given file

    Variables:
    sha256       => A resource locator for the file (sha256)

    Arguments:
    None

    Data Block:     => Dict of list of unique labels to update as comma separated string
    {
        "attribution": ["Qakbot"],
        "technique": ["Downloader"],
        "info": ["ARM"]
    }

    API call example:
    /api/v4/file/labels/123456...654321/

    Result example:
    {
        "success": true
        "labels": ["Qakbot", "Downloader", "ARM"],
        "label_categories": {
            "attribution": ["Qakbot"],
            "technique": ["Downloader"],
            "info": ["ARM"]
        }
    }
    """
    user = kwargs['user']

    file_obj = STORAGE.file.get_if_exists(sha256, as_obj=False, index_type=Index.ARCHIVE)

    if not file_obj:
        return make_api_response({"success": False}, err="File ID %s not found" % sha256, status_code=404)

    if not Classification.is_accessible(user['classification'], file_obj['classification']):
        return make_api_response("", "You are not allowed to change this file's labels...", 403)

    try:
        json_categories = {k: v for k, v in request.json.items() if k in LABEL_CATEGORIES}
        json_labels = {x for v in json_categories.values() for x in v}
    except ValueError:
        return make_api_response({"success": False}, err="Invalid list of labels received.", status_code=400)

    update_data = []
    for category in LABEL_CATEGORIES:
        for value in set(json_categories[category]) - set(file_obj['label_categories'][category]):
            update_data += [(STORAGE.file.UPDATE_APPEND_IF_MISSING, f'label_categories.{category}', value)]
        for value in set(file_obj['label_categories'][category]) - set(json_categories[category]):
            update_data += [(STORAGE.file.UPDATE_REMOVE, f'label_categories.{category}', value)]

    for value in set(json_labels) - set(file_obj['labels']):
        update_data += [(STORAGE.file.UPDATE_APPEND_IF_MISSING, 'labels', value)]
    for value in set(file_obj['labels']) - set(json_labels):
        update_data += [(STORAGE.file.UPDATE_REMOVE, 'labels', value)]

    STORAGE.file.update(sha256, update_data, index_type=Index.ARCHIVE)
    values = STORAGE.file.get(sha256, as_obj=False, index_type=Index.ARCHIVE)

    return make_api_response(dict(labels=values['labels'], label_categories=values['label_categories']))


@archive_api.route("/label/<sha256>/", methods=["PUT"])
@api_login(allow_readonly=False, require_role=[ROLES.file_detail])
def add_labels(sha256, **kwargs):
    """
    Add one or multiple labels to a given file

    Variables:
    sha256       => A resource locator for the file (sha256)

    Arguments:
    None

    Data Block:     => Dict of list of unique labels to update as comma separated string
    {
        "attribution": ["Qakbot"],
        "technique": ["Downloader"],
        "info": ["ARM"]
    }

    API call example:
    /api/v4/file/labels/123456...654321/

    Result example:
    {
        "success": true
        "labels": ["Qakbot", "Downloader", "ARM"],
        "label_categories": {
            "attribution": ["Qakbot"],
            "technique": ["Downloader"],
            "info": ["ARM"]
        }
    }
    """
    user = kwargs['user']

    file_obj = STORAGE.file.get(sha256, as_obj=False, index_type=Index.ARCHIVE)

    if not file_obj:
        return make_api_response({"success": False}, err="File ID %s not found" % sha256, status_code=404)

    if not Classification.is_accessible(user['classification'], file_obj['classification']):
        return make_api_response("", "You are not allowed to add labels to this file...", 403)

    update_data = []
    try:
        update_data += [
            (STORAGE.file.UPDATE_APPEND_IF_MISSING, f'label_categories.{category}', value) for category,
            values in request.json.items() if category in LABEL_CATEGORIES for value in values]
        update_data += [
            (STORAGE.file.UPDATE_APPEND_IF_MISSING, 'labels', value) for category,
            values in request.json.items() if category in LABEL_CATEGORIES for value in values]
    except ValueError:
        return make_api_response({"success": False}, err="Invalid list of labels received.", status_code=400)

    STORAGE.file.update(sha256, update_data, index_type=Index.ARCHIVE)
    values = STORAGE.file.get(sha256, as_obj=False, index_type=Index.ARCHIVE)

    return make_api_response(dict(labels=values['labels'], label_categories=values['label_categories']))


@archive_api.route("/label/<sha256>/", methods=["DELETE"])
@api_login(allow_readonly=False, require_role=[ROLES.file_detail])
def remove_labels(sha256, **kwargs):
    """
    Remove one or multiple labels to a given file

    Variables:
    sha256       => A resource locator for the file (sha256)

    Arguments:
    None

    Data Block:     => Dict of list of unique labels to update as comma separated string
    {
        "attribution": ["Qakbot"],
        "technique": ["Downloader"],
        "info": ["ARM"]
    }

    API call example:
    /api/v4/file/labels/123456...654321/

    Result example:
    {
        "success": true
        "labels": ["Qakbot", "Downloader", "ARM"],
        "label_categories": {
            "attribution": ["Qakbot"],
            "technique": ["Downloader"],
            "info": ["ARM"]
        }
    }
    """
    user = kwargs['user']

    file_obj = STORAGE.file.get(sha256, as_obj=False, index_type=Index.ARCHIVE)

    if not file_obj:
        return make_api_response({"success": False}, err="File ID %s not found" % sha256, status_code=404)

    if not Classification.is_accessible(user['classification'], file_obj['classification']):
        return make_api_response("", "You are not allowed to remove labels from this file...", 403)

    update_data = []
    try:
        update_data += [
            (STORAGE.file.UPDATE_REMOVE, f'label_categories.{category}', value) for category,
            values in request.json.items() if category in LABEL_CATEGORIES for value in values]
        update_data += [
            (STORAGE.file.UPDATE_REMOVE, 'labels', value) for category,
            values in request.json.items() if category in LABEL_CATEGORIES for value in values]
    except ValueError:
        return make_api_response({"success": False}, err="Invalid list of labels received.", status_code=400)

    STORAGE.file.update(sha256, update_data, index_type=Index.ARCHIVE)
    values = STORAGE.file.get(sha256, as_obj=False, index_type=Index.ARCHIVE)

    return make_api_response(dict(labels=values['labels'], label_categories=values['label_categories']))

