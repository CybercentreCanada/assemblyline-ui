
import hashlib
from flask import request

from assemblyline.common.isotime import now_as_iso
from assemblyline.remote.datatypes.lock import Lock
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import CLASSIFICATION, STORAGE

SUB_API = 'safelist'
safelist_api = make_subapi_blueprint(SUB_API, api_version=4)
safelist_api._doc = "Perform operations on safelisted hashes"


class InvalidSafehash(Exception):
    pass


def _merge_safe_hashes(new, old):
    try:
        # Check if hash types match
        if new['type'] != old['type']:
            raise InvalidSafehash(f"Safe hash type mismatch: {new['type']} != {old['type']}")

        # Use max classification
        old['classification'] = CLASSIFICATION.max_classification(old['classification'], new['classification'])

        # Update updated time
        old['updated'] = now_as_iso()

        # Update hashes
        old['hashes'].update(new['hashes'])

        # Update type specific info
        if old['type'] == 'file':
            old.setdefault('file', {})
            new_names = new.get('file', {}).pop('name', [])
            if 'name' in old['file']:
                for name in new_names:
                    if name not in old['file']['name']:
                        old['file']['name'].append(name)
            elif new_names:
                old['file']['name'] = new_names
            old['file'].update(new.get('file', {}))
        elif old['type'] == 'tag':
            old['tag'] = new['tag']

        # Merge sources
        src_map = {x['name']: x for x in new['sources']}
        if not src_map:
            raise InvalidSafehash("No valid source found")

        old_src_map = {x['name']: x for x in old['sources']}
        for name, src in src_map.items():
            src_cl = src.get('classification', None)
            if src_cl:
                old['classification'] = CLASSIFICATION.max_classification(old['classification'], src_cl)

            if name not in old_src_map:
                old_src_map[name] = src
            else:
                old_src = old_src_map[name]
                if old_src['type'] != src['type']:
                    raise InvalidSafehash(f"Source {name} has a type conflict: {old_src['type']} != {src['type']}")

                for reason in src['reason']:
                    if reason not in old_src['reason']:
                        old_src['reason'].append(reason)
        old['sources'] = old_src_map.values()
        return old
    except Exception as e:
        raise InvalidSafehash(f"Invalid data provided: {str(e)}")


@safelist_api.route("/", methods=["PUT", "POST"])
@api_login(require_type=['user', 'signature_importer'], allow_readonly=False, required_priv=["W"])
def add_or_update_hash(**kwargs):
    """
    Add a hash in the safelist if it does not exist or update its list of sources if it does

    Arguments:
    None

    Data Block:
    {
     "classification": "TLP:W",    # Classification of the safe hash (Computed for the mix of sources) - Optional
     "enabled": true,              # Is the safe hash enabled or not
     "file": {                     # Information about the file  - Only used in file mode
       "name": ["file.txt"]            # Possible names for the file
       "size": 12345,                  # Size of the file
       "type": "document/text"},       # Type of the file
     },
     "hashes": {                   # Information about the safe hash - At least one hash required
       "md5": "123...321",             # MD5 hash of the safe hash
       "sha1": "1234...4321",          # SHA1 hash of the safe hash
       "sha256": "12345....54321",     # SHA256 of the safe hash
     "sources": [                  # List of sources for why the file is safelisted, dedupped on name - Required
       {"classification": "TLP:W",     # Classification of the source (default: TLP:W) - Optional
        "name": "NSRL",                # Name of external source or user who safelisted it - Required
        "reason": [                    # List of reasons why the source is safelisted - Required
          "Found as test.txt on default windows 10 CD",
          "Found as install.txt on default windows XP CD"
        ],
        "type": "external"},           # Type or source (external or user) - Required
       {"classification": "TLP:W",
        "name": "admin",
        "reason": ["We've seen this file many times and it leads to False positives"],
        "type": "user"}
     ],
     "signature": {               # Signature information  - Only used in signature mode
       "name": "Avira.Eicar",         # Name of signature
     },
     "tag": {                     # Tag information  - Only used in tag mode
         "type": "network.url",        # Type of tag
         "value": "google.ca"          # Value of the tag
     },
     "type": "tag"                # Type of safelist hash (tag or file)
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
    data.setdefault('hashes', {})
    if data['type'] == 'tag':
        tag_data = data.get('tag', None)
        if tag_data is None or 'type' not in tag_data or 'value' not in tag_data:
            return make_api_response(None, "Tag data not found", 400)

        hashed_value = f"{tag_data['type']}: {tag_data['value']}".encode('utf8')
        data['hashes']['md5'] = hashlib.md5(hashed_value).hexdigest()
        data['hashes']['sha1'] = hashlib.sha1(hashed_value).hexdigest()
        data['hashes']['sha256'] = hashlib.sha256(hashed_value).hexdigest()
        data.pop('file', None)
        data.pop('signature', None)

    elif data['type'] == 'signature':
        sig_data = data.get('signature', None)
        if sig_data is None or 'name' not in sig_data:
            return make_api_response(None, "Signature data not found", 400)

        hashed_value = f"signature: {sig_data['name']}".encode('utf8')
        data['hashes']['md5'] = hashlib.md5(hashed_value).hexdigest()
        data['hashes']['sha1'] = hashlib.sha1(hashed_value).hexdigest()
        data['hashes']['sha256'] = hashlib.sha256(hashed_value).hexdigest()
        data.pop('tag', None)
        data.pop('file', None)

    elif data['type'] == 'file':
        data.pop('tag', None)
        data.pop('signature', None)
        data.setdefault('file', {})

    data['added'] = data['updated'] = now_as_iso()

    # Find the best hash to use for the key
    qhash = data['hashes'].get('sha256', data['hashes'].get('sha1', data['hashes'].get('md5', None)))
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

        src_cl = src.get('classification', None)
        if src_cl:
            data['classification'] = CLASSIFICATION.max_classification(data['classification'], src_cl)

        src_map[src['name']] = src

    with Lock(f'add_or_update-safelist-{qhash}', 30):
        old = STORAGE.safelist.get_if_exists(qhash, as_obj=False)
        if old:
            try:
                # Save data to the DB
                STORAGE.safelist.save(qhash, _merge_safe_hashes(data, old))
                return make_api_response({'success': True, "op": "update"})
            except InvalidSafehash as e:
                return make_api_response({}, str(e), 400)
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
      "classification": "TLP:W",    # Classification of the safe hash (Computed for the mix of sources) - Optional
      "enabled": true,              # Is the safe hash enabled or not
      "file": {                     # Information about the file  - Only used in file mode
        "name": ["file.txt"]            # Possible names for the file
        "size": 12345,                  # Size of the file
        "type": "document/text"},       # Type of the file
      },
      "hashes": {                   # Information about the safe hash - At least one hash required
        "md5": "123...321",             # MD5 hash of the safe hash
        "sha1": "1234...4321",          # SHA1 hash of the safe hash
        "sha256": "12345....54321",     # SHA256 of the safe hash
      "sources": [                  # List of sources for why the file is safelisted, dedupped on name - Required
        {"classification": "TLP:W",     # Classification of the source (default: TLP:W) - Optional
         "name": "NSRL",                # Name of external source or user who safelisted it - Required
         "reason": [                    # List of reasons why the source is safelisted - Required
           "Found as test.txt on default windows 10 CD",
           "Found as install.txt on default windows XP CD"
         ],
          "type": "external"},          # Type or source (external or user) - Required
        {"classification": "TLP:W",
         "name": "admin",
         "reason": ["We've seen this file many times and it leads to False positives"],
         "type": "user"}
      ],
      "signature": {                # Signature information  - Only used in signature mode
        "name": "Avira.Eicar",          # Name of signature
      },
      "tag": {                      # Tag information  - Only used in tag mode
          "type": "network.url",        # Type of tag
          "value": "google.ca"          # Value of the tag
      },
      "type": "tag"                 # Type of safelist hash (tag or file)
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
        if hash_data['type'] == 'tag':
            hash_data.pop('file', None)
            hash_data.pop('signature', None)
        elif hash_data['type'] == 'file':
            hash_data.pop('tag', None)
            hash_data.pop('signature', None)
        elif hash_data['type'] == 'signature':
            hash_data.pop('tag', None)
            hash_data.pop('file', None)

        # Find the hash used for the key
        key = hash_data['hashes'].get('sha256', hash_data['hashes'].get('sha1', hash_data['hashes'].get('md5', None)))
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
        old_val = old_data.get(key, {'classification': CLASSIFICATION.UNRESTRICTED,
                                     'hashes': {}, 'sources': [], 'type': val['type']})

        # Add upsert operation
        try:
            plan.add_upsert_operation(key, _merge_safe_hashes(val, old_val))
        except InvalidSafehash as e:
            return make_api_response("", str(e), 400)

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
     "classification": "TLP:W",    # Classification of the safe hash (Computed for the mix of sources) - Optional
     "enabled": true,              # Is the safe hash enabled or not
     "file": {                     # Information about the file  - Only used in file mode
       "name": ["file.txt"]            # Possible names for the file
       "size": 12345,                  # Size of the file
       "type": "document/text"},       # Type of the file
     },
     "hashes": {                   # Information about the safe hash - At least one hash required
       "md5": "123...321",             # MD5 hash of the safe hash
       "sha1": "1234...4321",          # SHA1 hash of the safe hash
       "sha256": "12345....54321",     # SHA256 of the safe hash
     "sources": [                  # List of sources for why the file is safelisted, dedupped on name - Required
       {"classification": "TLP:W",     # Classification of the source (default: TLP:W) - Optional
        "name": "NSRL",                # Name of external source or user who safelisted it - Required
        "reason": [                    # List of reasons why the source is safelisted - Required
          "Found as test.txt on default windows 10 CD",
          "Found as install.txt on default windows XP CD"
        ],
        "type": "external"},           # Type or source (external or user) - Required
       {"classification": "TLP:W",
        "name": "admin",
        "reason": ["We've seen this file many times and it leads to False positives"],
        "type": "user"}
     ],
     "signature": {               # Signature information  - Only used in signature mode
       "name": "Avira.Eicar",         # Name of signature
     },
     "tag": {                     # Tag information  - Only used in tag mode
         "type": "network.url",       # Type of tag
         "value": "google.ca"         # Value of the tag
     },
     "type": "tag"                # Type of safelist hash (tag or file)
    }
    """
    if len(qhash) not in [64, 40, 32]:
        return make_api_response(None, "Invalid hash length", 400)

    safelist = STORAGE.safelist.get_if_exists(qhash, as_obj=False)
    if safelist and CLASSIFICATION.is_accessible(kwargs['user']['classification'], safelist['classification']):
        return make_api_response(safelist)

    return make_api_response(None, "The hash was not found in the safelist.", 404)


@safelist_api.route("/enable/<qhash>/", methods=["PUT"])
@api_login(allow_readonly=False)
def set_hash_status(qhash, **kwargs):
    """
    Set the enabled status of a hash

    Variables:
    qhash       => Hash to change the status

    Arguments:
    None

    Data Block:
    "true"

    Result example:
    {"success": True}
    """
    user = kwargs['user']
    data = request.json

    if len(qhash) not in [64, 40, 32]:
        return make_api_response(None, "Invalid hash length", 400)

    if 'admin' in user['type'] or 'signature_manager' in user['type']:
        return make_api_response({'success': STORAGE.safelist.update(
            qhash, [(STORAGE.safelist.UPDATE_SET, 'enabled', data)])})

    return make_api_response({}, "You are not allowed to change the status", 403)


@safelist_api.route("/<qhash>/", methods=["DELETE"])
@api_login(allow_readonly=False)
def delete_hash(qhash, **kwargs):
    """
    Delete a hash from the safelist

    Variables:
    qhash       => Hash to check

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
