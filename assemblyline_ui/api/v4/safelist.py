
import hashlib
import re
from urllib.parse import unquote

from flask import request

from assemblyline.common.isotime import now_as_iso
from assemblyline.odm.models.user import ROLES
from assemblyline.remote.datatypes.lock import Lock
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline.datastore.exceptions import VersionConflictException
from assemblyline_ui.config import CLASSIFICATION, LOGGER, STORAGE, DEFAULT_SAFELIST_TAG_EXPIRY

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

        # Use the new classification but we will recompute it later anyway
        old['classification'] = new['classification']

        # Update updated time
        old['updated'] = new.get('updated', now_as_iso())

        # Update hashes
        old['hashes'].update({k: v for k, v in new['hashes'].items() if v})

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
            old['file'].update({k: v for k, v in new.get('file', {}).items() if v})
        elif old['type'] == 'tag':
            old['tag'] = new['tag']

        # Merge sources
        src_map = {x['name']: x for x in new['sources']}
        if not src_map:
            raise InvalidSafehash("No valid source found")

        old_src_map = {x['name']: x for x in old['sources']}
        for name, src in src_map.items():
            if name not in old_src_map:
                old_src_map[name] = src
            else:
                old_src = old_src_map[name]
                if old_src['type'] != src['type']:
                    raise InvalidSafehash(f"Source {name} has a type conflict: {old_src['type']} != {src['type']}")

                for reason in src['reason']:
                    if reason not in old_src['reason']:
                        old_src['reason'].append(reason)
                old_src['classification'] = src.get('classification', old_src['classification'])
        old['sources'] = list(old_src_map.values())

        # Calculate the new classification
        for src in old['sources']:
            old['classification'] = CLASSIFICATION.max_classification(
                old['classification'], src.get('classification', None))

        # Set the expiry
        old['expiry_ts'] = new.get('expiry_ts', None)
        return old
    except Exception as e:
        raise InvalidSafehash(f"Invalid data provided: {str(e)}")


@safelist_api.route("/", methods=["POST", "PUT"])
@api_login(audit=False, require_role=[ROLES.safelist_manage], allow_readonly=False)
def add_or_update_hash(**kwargs):
    """
    Add a hash in the safelist if it does not exist or update its list of sources if it does

    Arguments:
    None

    Data Block:
    {
     "classification": "TLP:C",    # Classification of the safe hash (Computed for the mix of sources) - Optional
     "enabled": true,              # Is the safe hash enabled or not
     "dtl": 0,                     # Days to live for the safelist item (0: forever)
     "file": {                     # Information about the file  - Only used in file mode
       "name": ["file.txt"]            # Possible names for the file
       "size": 12345,                  # Size of the file
       "type": "document/text"},       # Type of the file
     },
     "hashes": {                   # Information about the safe hash - At least one hash required
       "md5": "123...321",             # MD5 of the safe hash
       "sha1": "1234...4321",          # SHA1 of the safe hash
       "sha256": "12345....54321",     # SHA256 of the safe hash
     "sources": [                  # List of sources for why the file is safelisted, dedupped on name - Required
       {"classification": "TLP:C",     # Classification of the source (default: TLP:C) - Optional
        "name": "NSRL",                # Name of external source or user who safelisted it - Required
        "reason": [                    # List of reasons why the source is safelisted - Required
          "Found as test.txt on default windows 10 CD",
          "Found as install.txt on default windows XP CD"
        ],
        "type": "external"},           # Type or source (external or user) - Required
       {"classification": "TLP:C",
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
     "op": "add",             # Was it added to the system or updated
     "hash": "1234...4321"    # Hash that was used to store the safelist item
    }
    """
    # Load data
    data = request.json
    user = kwargs['user']

    # Set defaults
    data['classification'] = CLASSIFICATION.UNRESTRICTED
    data.setdefault('hashes', {})
    data.setdefault('expiry_ts', None)
    if data['type'] == 'tag':
        # Remove file related fields
        data.pop('file', None)
        data.pop('hashes', None)
        data.pop('signature', None)

        tag_data = data.get('tag', None)
        if tag_data is None or 'type' not in tag_data or 'value' not in tag_data:
            return make_api_response(None, "Tag data not found", 400)

        hashed_value = f"{tag_data['type']}: {tag_data['value']}".encode('utf8')
        data['hashes'] = {
            'md5': hashlib.md5(hashed_value).hexdigest(),
            'sha1': hashlib.sha1(hashed_value).hexdigest(),
            'sha256': hashlib.sha256(hashed_value).hexdigest()
        }

    elif data['type'] == 'signature':
        # Remove file related fields
        data.pop('file', None)
        data.pop('hashes', None)
        data.pop('tag', None)

        sig_data = data.get('signature', None)
        if sig_data is None or 'name' not in sig_data:
            return make_api_response(None, "Signature data not found", 400)

        hashed_value = f"signature: {sig_data['name']}".encode('utf8')
        data['hashes'] = {
            'md5': hashlib.md5(hashed_value).hexdigest(),
            'sha1': hashlib.sha1(hashed_value).hexdigest(),
            'sha256': hashlib.sha256(hashed_value).hexdigest()
        }

    elif data['type'] == 'file':
        data.pop('signature', None)
        data.pop('tag', None)
        data.setdefault('file', {})

    # Ensure expiry_ts is set on tag-related items
    dtl = data.pop('dtl', None) or DEFAULT_SAFELIST_TAG_EXPIRY
    if dtl:
        data['expiry_ts'] = now_as_iso(dtl)

    # Set last updated
    data['added'] = data['updated'] = now_as_iso()

    # Find the best hash to use for the key
    for hash_key in ['sha256', 'sha1', 'md5']:
        qhash = data['hashes'].get(hash_key, None)
        if qhash:
            break

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
            if ROLES.signature_import not in user['roles']:
                return make_api_response(
                    {}, "You do not have sufficient priviledges to add an external source.", 403)

        # Find the highest classification of all sources
        data['classification'] = CLASSIFICATION.max_classification(
            data['classification'], src.get('classification', None))

        src_map[src['name']] = src

    with Lock(f'add_or_update-safelist-{qhash}', 30):
        old = STORAGE.safelist.get_if_exists(qhash, as_obj=False)
        if old:
            try:
                # Save data to the DB
                STORAGE.safelist.save(qhash, _merge_safe_hashes(data, old))
                return make_api_response({'success': True, "op": "update", 'hash': qhash})
            except InvalidSafehash as e:
                return make_api_response({}, str(e), 400)
        else:
            try:
                data['sources'] = src_map.values()
                STORAGE.safelist.save(qhash, data)
                return make_api_response({'success': True, "op": "add", 'hash': qhash})
            except Exception as e:
                return make_api_response({}, f"Invalid data provided: {str(e)}", 400)


@safelist_api.route("/add_update_many/", methods=["POST", "PUT"])
@api_login(audit=False, allow_readonly=False, require_role=[ROLES.safelist_manage])
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
      "classification": "TLP:C",    # Classification of the safe hash (Computed for the mix of sources) - Optional
      "enabled": true,              # Is the safe hash enabled or not
      "dtl": 0,                     # Days to live for the safelist item (0: forever)
      "file": {                     # Information about the file  - Only used in file mode
        "name": ["file.txt"]            # Possible names for the file
        "size": 12345,                  # Size of the file
        "type": "document/text"},       # Type of the file
      },
      "hashes": {                   # Information about the safe hash - At least one hash required
        "md5": "123...321",             # MD5 of the safe hash
        "sha1": "1234...4321",          # SHA1 of the safe hash
        "sha256": "12345....54321",     # SHA256 of the safe hash
      "sources": [                  # List of sources for why the file is safelisted, dedupped on name - Required
        {"classification": "TLP:C",     # Classification of the source (default: TLP:C) - Optional
         "name": "NSRL",                # Name of external source or user who safelisted it - Required
         "reason": [                    # List of reasons why the source is safelisted - Required
           "Found as test.txt on default windows 10 CD",
           "Found as install.txt on default windows XP CD"
         ],
          "type": "external"},          # Type or source (external or user) - Required
        {"classification": "TLP:C",
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
        hash_data.setdefault('hashes', {})
        hash_data.setdefault('expiry_ts', None)

        if hash_data['type'] == 'tag':
            # Remove file related fields
            hash_data.pop('file', None)
            hash_data.pop('hashes', None)
            hash_data.pop('signature', None)

            tag_data = hash_data.get('tag', None)
            if tag_data is None or 'type' not in tag_data or 'value' not in tag_data:
                return make_api_response(None, f"Invalid or missing tag data. ({hash_data})", 400)

            hashed_value = f"{tag_data['type']}: {tag_data['value']}".encode('utf8')
            hash_data['hashes'] = {
                'md5': hashlib.md5(hashed_value).hexdigest(),
                'sha1': hashlib.sha1(hashed_value).hexdigest(),
                'sha256': hashlib.sha256(hashed_value).hexdigest()
            }

            # Ensure expiry_ts is set on tag-related items
            hash_data['expiry_ts'] = hash_data.get('expiry_ts', now_as_iso(DEFAULT_SAFELIST_TAG_EXPIRY))
        elif hash_data['type'] == 'file':
            # Remove tag and signature related fields
            hash_data.pop('signature', None)
            hash_data.pop('tag', None)
            hash_data.setdefault('file', {})
        elif hash_data['type'] == 'signature':
            # Remove file and tag related fields
            hash_data.pop('file', None)
            hash_data.pop('hashes', None)
            hash_data.pop('tag', None)

            sig_data = hash_data.get('signature', None)
            if sig_data is None or 'name' not in sig_data:
                return make_api_response(None, f"Invalid or missing signature data. ({hash_data})", 400)

            hashed_value = f"signature: {sig_data['name']}".encode('utf8')
            hash_data['hashes'] = {
                'md5': hashlib.md5(hashed_value).hexdigest(),
                'sha1': hashlib.sha1(hashed_value).hexdigest(),
                'sha256': hashlib.sha256(hashed_value).hexdigest()
            }
        else:
            return make_api_response("", f"Invalid hash type: {hash_data['type']}", 400)

        # Ensure expiry_ts is set on tag-related items
        dtl = hash_data.pop('dtl', None) or DEFAULT_SAFELIST_TAG_EXPIRY
        if dtl:
            hash_data['expiry_ts'] = now_as_iso(dtl)

        # Set last updated
        hash_data['added'] = hash_data['updated'] = now_as_iso()

        # Find the hash used for the key
        hashes = hash_data.get('hashes', {})
        for hash_key in ['sha256', 'sha1', 'md5']:
            key = hashes.get(hash_key, None)
            if key:
                break

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
@api_login(require_role=[ROLES.safelist_view])
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
     "classification": "TLP:C",    # Classification of the safe hash (Computed for the mix of sources) - Optional
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
       {"classification": "TLP:C",     # Classification of the source (default: TLP:C) - Optional
        "name": "NSRL",                # Name of external source or user who safelisted it - Required
        "reason": [                    # List of reasons why the source is safelisted - Required
          "Found as test.txt on default windows 10 CD",
          "Found as install.txt on default windows XP CD"
        ],
        "type": "external"},           # Type or source (external or user) - Required
       {"classification": "TLP:C",
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


@safelist_api.route("/signature/<signature_name>/", methods=["GET"])
@api_login(require_role=[ROLES.safelist_view])
def check_signature_exists(signature_name, **kwargs):
    """
    Check if a signature exists in the safelist.

    Variables:
    signature_name      => Value of the tag to search for

    Arguments:
    None

    Data Block:
    None

    API call example:
    GET /api/v1/safelist/network.static.ip/1.1.1.1/

    Result example:
    {
     "classification": "TLP:C",    # Classification of the safe hash (Computed for the mix of sources) - Optional
     "enabled": true,              # Is the safe hash enabled or not
     "hashes": {                   # Information about the safe hash
       "md5": "123...321",             # MD5 hash of the safe hash
       "sha1": "1234...4321",          # SHA1 hash of the safe hash
       "sha256": "12345....54321",     # SHA256 of the safe hash
     "sources": [                  # List of sources for why the file is safelisted, dedupped on name - Required
       {"classification": "TLP:C",     # Classification of the source (default: TLP:C) - Optional
        "name": "NSRL",                # Name of external source or user who safelisted it - Required
        "reason": [                    # List of reasons why the source is safelisted - Required
          "Found as test.txt on default windows 10 CD",
          "Found as install.txt on default windows XP CD"
        ],
        "type": "external"},           # Type or source (external or user) - Required
       {"classification": "TLP:C",
        "name": "admin",
        "reason": ["We've seen this file many times and it leads to False positives"],
        "type": "user"}
     ],
     "signature": {                 # Signature information
         "name": "network.url",       # Name of the signature
     },
     "type": "signature"                # Type of safelist hash
    }
    """
    qhash = hashlib.sha256(f"signature: {unquote(signature_name)}".encode('utf8')).hexdigest()

    safelist = STORAGE.safelist.get_if_exists(qhash, as_obj=False)
    if safelist and CLASSIFICATION.is_accessible(kwargs['user']['classification'], safelist['classification']):
        return make_api_response(safelist)

    return make_api_response(None, "The hash was not found in the safelist.", 404)


@safelist_api.route("/<tag_type>/<tag_value>/", methods=["GET"])
@api_login(require_role=[ROLES.safelist_view])
def check_tag_exists(tag_type, tag_value, **kwargs):
    """
    Check if a tag exists in the safelist.

    Variables:
    tag_type       => Type of tag to search for
    tag_value      => Value of the tag to search for

    Arguments:
    None

    Data Block:
    None

    API call example:
    GET /api/v1/safelist/network.static.ip/1.1.1.1/

    Result example:
    {
     "classification": "TLP:C",    # Classification of the safe hash (Computed for the mix of sources) - Optional
     "enabled": true,              # Is the safe hash enabled or not
     "hashes": {                   # Information about the safe hash
       "md5": "123...321",             # MD5 hash of the safe hash
       "sha1": "1234...4321",          # SHA1 hash of the safe hash
       "sha256": "12345....54321",     # SHA256 of the safe hash
     "sources": [                  # List of sources for why the file is safelisted, dedupped on name - Required
       {"classification": "TLP:C",     # Classification of the source (default: TLP:C) - Optional
        "name": "NSRL",                # Name of external source or user who safelisted it - Required
        "reason": [                    # List of reasons why the source is safelisted - Required
          "Found as test.txt on default windows 10 CD",
          "Found as install.txt on default windows XP CD"
        ],
        "type": "external"},           # Type or source (external or user) - Required
       {"classification": "TLP:C",
        "name": "admin",
        "reason": ["We've seen this file many times and it leads to False positives"],
        "type": "user"}
     ],
     "tag": {                     # Tag information  - Only used in tag mode
         "type": "network.url",       # Type of tag
         "value": "google.ca"         # Value of the tag
     },
     "type": "tag"                # Type of safelist hash (tag or file)
    }
    """
    qhash = hashlib.sha256(f"{tag_type}: {unquote(tag_value)}".encode('utf8')).hexdigest()

    safelist = STORAGE.safelist.get_if_exists(qhash, as_obj=False)
    if safelist and CLASSIFICATION.is_accessible(kwargs['user']['classification'], safelist['classification']):
        return make_api_response(safelist)

    return make_api_response(None, "The hash was not found in the safelist.", 404)


@safelist_api.route("/enable/<qhash>/", methods=["PUT"])
@api_login(allow_readonly=False, require_role=[ROLES.safelist_manage])
def set_hash_status(qhash, **_):
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
    data = request.json

    if len(qhash) not in [64, 40, 32]:
        return make_api_response(None, "Invalid hash length", 400)

    return make_api_response({'success': STORAGE.safelist.update(
        qhash, [
            (STORAGE.safelist.UPDATE_SET, 'enabled', data),
            (STORAGE.safelist.UPDATE_SET, 'updated', now_as_iso()),
        ])})


@safelist_api.route("/expiry/<qhash>/", methods=["DELETE"])
@api_login(allow_readonly=False, require_role=[ROLES.safelist_manage])
def clear_expiry(qhash, **_):
    """
    Clear the expiry date of a hash

    Variables:
    qhash       => Hash to clear the expiry date from

    Arguments:
    None

    Data Block:
    None

    Result example:
    {"success": True}
    """
    if len(qhash) not in [64, 40, 32]:
        return make_api_response(None, "Invalid hash length", 400)

    return make_api_response({'success': STORAGE.safelist.update(
        qhash, [
            (STORAGE.safelist.UPDATE_SET, 'expiry_ts', None),
            (STORAGE.safelist.UPDATE_SET, 'updated', now_as_iso())
        ])})


@safelist_api.route("/source/<qhash>/<source>/<stype>/", methods=["DELETE"])
@api_login(allow_readonly=False, require_role=[ROLES.safelist_manage])
def remove_source(qhash, source, stype, **kwargs):
    """
    Remove a source from the specified safelist item

    Variables:
    qhash       => Hash to remove the source from
    source      => Name of the source to remove
    stype       => Type of source to remove

    Arguments:
    None

    Data Block:
    None

    Result example:
    {"success": True}
    """
    user = kwargs['user']

    if len(qhash) not in [64, 40, 32]:
        return make_api_response(None, "Invalid hash length", 400)

    if (source != user['uname'] or stype != 'user') and ROLES.administration not in user['roles']:
        return make_api_response(
            None, "You are not allowed to remove this source from this safelist item", 403)

    while True:
        current_safelist, version = STORAGE.safelist.get_if_exists(qhash, as_obj=False, version=True)
        if not current_safelist:
            return make_api_response({}, "The safelist item your are trying to modify does not exists", 404)

        if not CLASSIFICATION.is_accessible(user['classification'], current_safelist['classification']):
            return make_api_response(
                None, "You are not allowed to remove sources from this safelist item", 403)

        if len(current_safelist['sources']) == 1:
            return make_api_response(
                None, "You are not allowed to remove the last source from this safelist item", 403)

        found = -1
        max_classification = CLASSIFICATION.UNRESTRICTED
        for (src_id, src) in enumerate(current_safelist['sources']):
            if src['name'] == source and src['type'] == stype:
                found = src_id
            else:
                max_classification = CLASSIFICATION.max_classification(
                    max_classification, src.get('classification', max_classification))
        current_safelist['classification'] = max_classification

        if found == -1:
            return make_api_response({}, "The specified source does not exist in the specified safelist item", 404)

        current_safelist['sources'].pop(found)
        current_safelist['updated'] = now_as_iso()

        try:
            return make_api_response({'success': STORAGE.safelist.save(qhash, current_safelist, version=version)})

        except VersionConflictException as vce:
            LOGGER.info(f"Retrying save or freshen due to version conflict: {str(vce)}")


@safelist_api.route("/classification/<qhash>/<source>/<stype>/", methods=["PUT"])
@api_login(allow_readonly=False, require_role=[ROLES.safelist_manage])
def set_classification(qhash, source, stype, **kwargs):
    """
    Change the classification of a safelist item source

    Variables:
    qhash       => Hash to change the classification of
    source      => Source to change the classification of
    stype       => Type of source to change the classification of

    Arguments:
    None

    Data Block:
    "TLP:CLEAR"

    Result example:
    {"success": True}
    """
    classification = request.json
    user = kwargs['user']

    if len(qhash) not in [64, 40, 32]:
        return make_api_response(None, "Invalid hash length", 400)

    if not CLASSIFICATION.is_valid(classification):
        return make_api_response(None, f"Classification {classification} is not valid.", 400)

    if not CLASSIFICATION.is_accessible(user['classification'], classification):
        return make_api_response(None, "You cannot set a classification that you don't have access to", 403)

    if (source != user['uname'] or stype != 'user') and ROLES.administration not in user['roles']:
        return make_api_response(
            None, "You are not allowed to change the classification for this safelist item", 403)

    while True:
        current_safelist, version = STORAGE.safelist.get_if_exists(qhash, as_obj=False, version=True)
        if not current_safelist:
            return make_api_response({}, "The safelist item your are trying to modify does not exists", 404)

        if not CLASSIFICATION.is_accessible(user['classification'], current_safelist['classification']):
            return make_api_response(
                None, "You are not allowed to change the classification for this safelist item", 403)

        found = False
        max_classification = classification
        for src in current_safelist['sources']:
            if src['name'] == source and src['type'] == stype:
                found = True
                src['classification'] = classification

            max_classification = CLASSIFICATION.max_classification(
                max_classification, src.get('classification', max_classification))

        if not found:
            return make_api_response({}, "The specified source does not exist in the specified safelist item", 404)

        current_safelist['classification'] = max_classification
        current_safelist['updated'] = now_as_iso()

        try:
            return make_api_response({'success': STORAGE.safelist.save(qhash, current_safelist, version=version)})

        except VersionConflictException as vce:
            LOGGER.info(f"Retrying save or freshen due to version conflict: {str(vce)}")


@safelist_api.route("/expiry/<qhash>/", methods=["PUT"])
@api_login(allow_readonly=False, require_role=[ROLES.safelist_manage])
def set_expiry(qhash, **_):
    """
    Change the expiry date of a hash

    Variables:
    qhash       => Hash to change the expiry date

    Arguments:
    None

    Data Block:
    "2023-12-07T20:22:54.569242Z"

    Result example:
    {"success": True}
    """
    expiry = request.json

    if len(qhash) not in [64, 40, 32]:
        return make_api_response(None, "Invalid hash length", 400)

    if not re.match(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{6}Z', expiry):
        return make_api_response(
            None, "Invalid date format, must match ISO9660 format (0000-00-00T00:00:00.000000Z)", 400)

    return make_api_response({'success': STORAGE.safelist.update(
        qhash, [
            (STORAGE.safelist.UPDATE_SET, 'expiry_ts', expiry),
            (STORAGE.safelist.UPDATE_SET, 'updated', now_as_iso())
        ])})


@safelist_api.route("/<qhash>/", methods=["DELETE"])
@api_login(allow_readonly=False, require_role=[ROLES.safelist_manage])
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

    if ROLES.administration in user['roles'] or ROLES.signature_manage in user['roles']:
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
