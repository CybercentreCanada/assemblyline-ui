
from flask import request

from assemblyline.common.isotime import now_as_iso
from assemblyline.remote.datatypes.lock import Lock
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import CLASSIFICATION, STORAGE

SUB_API = 'safelist'
safelist_api = make_subapi_blueprint(SUB_API, api_version=4)
safelist_api._doc = "Perform operations on safelisted hashes"


@safelist_api.route("/", methods=["PUT", "POST"])
@api_login(require_type=['user', 'signature_importer'], allow_readonly=False, required_priv=["W"])
def add_or_update_hash(**kwargs):
    """
    Add a hash in the safelist if it does not exist or update its list of sources if it does

    Arguments:
    None

    Data Block:
    {
     "classification": "TLP:W",      # Classification of the file (default: TLP:W) - Optional
     "fileinfo": {                   # Information about the file - At least one hash required
       "md5": "123...321",             # MD5 hash of the file
       "sha1": "1234...4321",          # SHA1 hash of the file
       "sha256": "12345....54321",     # SHA256 of the file
       "size": 12345,                  # Size of the file
       "type": "document/text"},       # Type of the file
     "sources": [                    # List of sources for why the file is safelisted, dedupped on name - Required
       {"name": "NSRL",                # Name of external source or user who safelisted it - Required
        "reason": [                    # List of reasons why the source is safelisted - Required
          "Found as test.txt on default windows 10 CD",
          "Found as install.txt on default windows XP CD"
        ],
        "type": "external"},           # Type or source (external or user) - Required
       {"name": "admin",
        "reason": ["We've seen this file many times and it leads to False positives"],
        "type": "user"}
     ]
    }

    Result example:
    {
     "success": true,         # Was the hash successfully added
     "op": "add"              # Was it added to the system or updated
    }
    """
    # Load data
    data = request.json
    if not data:
        return make_api_response({}, "No data provided", 400)
    user = kwargs['user']

    # Set defaults
    data.setdefault('classification', CLASSIFICATION.UNRESTRICTED)
    data.setdefault('fileinfo', {})
    data['added'] = data['updated'] = now_as_iso()

    # Find the best hash to use for the key
    qhash = data['fileinfo'].get('sha256', data['fileinfo'].get('sha1', data['fileinfo'].get('md5', None)))
    # Validate hash length
    if not qhash:
        return make_api_response(None, "No valid hash found", 400)

    # Validate sources
    src_map = {}
    for src in data['sources']:
        if src['type'] == 'user':
            if src['name'] != user['uname']:
                return make_api_response(
                    {}, f"You cannot add a source for another user. {src['name']} != {user['uname']}", 400)
        else:
            if 'signature_importer' not in user['type']:
                return make_api_response(
                    {}, "You do not have sufficient priviledges to add an external source.", 403)

        src_map[src['name']] = src

    with Lock(f'add_or_update-safelist-{qhash}', 30):
        old = STORAGE.safelist.get_if_exists(qhash, as_obj=False)
        if old:
            try:
                # Use old added date
                data['added'] = old['added']

                # Use minimal classification
                data['classification'] = CLASSIFICATION.max_classification(
                    data['classification'], old['classification'])

                # Merge file info (keep new values)
                for k, v in old['fileinfo'].items():
                    if k not in data['fileinfo']:
                        data['fileinfo'][k] = v

                # Merge sources together
                old_src_map = {x['name']: x for x in old['sources']}
                for name, src in src_map.items():
                    if name not in old_src_map:
                        old_src_map[name] = src
                    else:
                        old_src = old_src_map[name]
                        if old_src['type'] != src['type']:
                            return make_api_response(
                                {}, f"Source {name} has a type conflict: {old_src['type']} != {src['type']}", 400)

                        for reason in src['reason']:
                            if reason not in old_src['reason']:
                                old_src['reason'].append(reason)

                data['sources'] = old_src_map.values()

                # Save data to the DB
                STORAGE.safelist.save(qhash, data)
                return make_api_response({'success': True, "op": "update"})
            except Exception as e:
                return make_api_response({}, f"Invalid data provided: {str(e)}", 400)
        else:
            try:
                data['sources'] = src_map.values()
                STORAGE.safelist.save(qhash, data)
                return make_api_response({'success': True, "op": "add"})
            except Exception as e:
                return make_api_response({}, f"Invalid data provided: {str(e)}", 400)


@safelist_api.route("/add_update_many/", methods=["POST", "PUT"])
@api_login(audit=False, required_priv=['W'], allow_readonly=False, require_type=['signature_importer'])
def add_update_many_hashes(**_):
    """
    Add or Update a list of the safe hashes

    Variables:
    None

    Arguments:
    None

    Data Block (REQUIRED):
    [                             # List of Safe hash blocks
     {
      "classification": "TLP:W",      # Classification of the file (default: TLP:W) - Optional
      "fileinfo": {                   # Information about the file - Optional
        "md5": "123...321",             # MD5 hash of the file
        "sha1": "1234...4321",          # SHA1 hash of the file
        "sha256": "12345....54321",     # SHA256 of the file (default: sha256 variable)
        "size": 12345,                  # Size of the file
        "type": "document/text"},       # Type of the file
      "sources": [                    # List of sources for why the file is safelisted, dedupped on name - Required
        {"name": "NSRL",                # Name of external source or user who safelisted it - Required
         "reason": [                    # List of reasons why the source is safelisted - Required
           "Found as test.txt on default windows 10 CD",
           "Found as install.txt on default windows XP CD"
         ],
         "type": "external"},           # Type or source (external or user) - Required
        {"name": "admin",
         "reason": ["We've seen this file many times and it leads to False positives"],
         "type": "user"}
      ]
     }
     ...
    ]

    Result example:
    {"success": 23,                # Number of hashes that succeeded
     "errors": []}                 # List of hashes that failed
    """
    data = request.json

    if not isinstance(data, list):
        return make_api_response("", "Could not get the list of hashes", 400)

    new_data = {}
    for hash_data in data:
        # Set a classification if None
        hash_data.setdefault('classification', CLASSIFICATION.UNRESTRICTED)

        # Find the hash used for the key
        fileinfo = hash_data.get('fileinfo', {})
        key = fileinfo.get('sha256', fileinfo.get('sha1', fileinfo.get('md5', None)))
        if not key:
            return make_api_response("", f"Invalid hash block: {str(hash_data)}", 400)

        # Save the new hash_block
        new_data[key] = hash_data

    # Get already existing hashes
    old_data = STORAGE.safelist.multiget(list(new_data.keys()), as_dictionary=True, as_obj=False,
                                         error_on_missing=False)

    # Test signature names
    plan = STORAGE.safelist.get_bulk_plan()
    for key, val in new_data.items():
        # Use maximum classification
        old_val = old_data.get(key, {'classification': CLASSIFICATION.UNRESTRICTED, 'fileinfo': {}, 'sources': []})
        old_val['classification'] = CLASSIFICATION.max_classification(
            old_val['classification'], val['classification'])

        # Update updated time
        old_val['updated'] = now_as_iso()

        # Update fileinfo
        old_val['fileinfo'].update(val['fileinfo'])

        # Merge sources
        src_map = {x['name']: x for x in val['sources'] if x['type'] == 'external'}
        if not src_map:
            make_api_response({}, f"No valid source found for {key}", 400)

        old_src_map = {x['name']: x for x in old_val['sources']}
        for name, src in src_map.items():
            if name not in old_src_map:
                old_src_map[name] = src
            else:
                old_src = old_src_map[name]
                if old_src['type'] != src['type']:
                    return make_api_response(
                        {}, f"Hash {key} source {name} has a type conflict: {old_src['type']} != {src['type']}", 400)

                for reason in src['reason']:
                    if reason not in old_src['reason']:
                        old_src['reason'].append(reason)
        old_val['sources'] = old_src_map.values()

        # Add upsert operation
        plan.add_upsert_operation(key, old_val)

    if not plan.empty:
        # Execute plan
        res = STORAGE.safelist.bulk(plan)
        return make_api_response({"success": len(res['items']), "errors": res['errors']})

    return make_api_response({"success": 0, "errors": []})


@safelist_api.route("/<qhash>/", methods=["GET"])
@api_login(required_priv=["R"])
def check_hash_exists(qhash, **kwargs):
    """
    Check if a hash exists in the safelist.

    Variables:
    qhash       => Hash to check is exist (either md5, sha1 or sha256)

    Arguments:
    None

    Data Block:
    None

    API call example:
    GET /api/v1/safelist/123456...654321/

    Result example:
    {
      "classification": "TLP:W",      # Classification of the file
      "fileinfo": {                   # Information about the file
        "md5": "123...321",             # MD5 hash of the file
        "sha1": "1234...4321",          # SHA1 hash of the file
        "sha256": "12345....54321",     # SHA256 of the file
        "size": 12345,                  # Size of the file
        "type": "document/text"},       # Type of the file
      "sources": [                    # List of sources for why the file is safelisted, dedupped on name
        {"name": "NSRL",                # Name of external source or user who safelisted it
         "reason": [                    # List of reasons why the source is safelisted
           "Found as test.txt on default windows 10 CD",
           "Found as install.txt on default windows XP CD"
         ],
         "type": "external"},           # Type or source (external or user)
        {"name": "admin",
         "reason": ["We've seen this file many times and it leads to False positives"],
         "type": "user"}
      ]
    }
    """
    if len(qhash) not in [64, 40, 32]:
        return make_api_response(None, "Invalid hash length", 400)

    safelist = STORAGE.safelist.get_if_exists(qhash, as_obj=False)
    if safelist and CLASSIFICATION.is_accessible(kwargs['user']['classification'], safelist['classification']):
        return make_api_response(safelist)

    return make_api_response(None, "The hash was not found in the safelist.", 404)


@safelist_api.route("/<qhash>/", methods=["DELETE"])
@api_login(allow_readonly=False)
def delete_hash(qhash, **kwargs):
    """
    Delete a hash from the safelist

    Variables:
    sha256       => Hash to check

    Arguments:
    None

    Data Block:
    None

    API call example:
    DELETE /api/v1/safelist/123456...654321/

    Result example:
    {"success": True}
    """
    user = kwargs['user']

    if len(qhash) not in [64, 40, 32]:
        return make_api_response(None, "Invalid hash length", 400)

    if 'admin' in user['type'] or 'signature_manager' in user['type']:
        return make_api_response({'success': STORAGE.safelist.delete(qhash)})
    else:
        safe_hash = STORAGE.safelist.get_if_exists(qhash, as_obj=False)
        if safe_hash:
            safe_hash['sources'] = [x for x in safe_hash['sources'] if x['name'] != user['uname']]
            if len(safe_hash['sources']) == 0:
                return make_api_response({'success': STORAGE.safelist.delete(qhash)})
            else:
                return make_api_response({'success': STORAGE.safelist.save(qhash, safe_hash)})

        return make_api_response({'success': False})
