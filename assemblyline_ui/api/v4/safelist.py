
import hashlib
import re
from urllib.parse import unquote

from flask import request

from assemblyline.common.isotime import now_as_iso
from assemblyline.odm.models.user import ROLES
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline.datastore.exceptions import VersionConflictException
from assemblyline_ui.config import CLASSIFICATION, LOGGER, STORAGE
from assemblyline_core.safelist_client import SafelistClient, InvalidSafehash

SUB_API = 'safelist'
safelist_api = make_subapi_blueprint(SUB_API, api_version=4)
safelist_api._doc = "Perform operations on safelisted hashes"

CLIENT = SafelistClient(datastore=STORAGE)


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

    try:
        qhash, op = CLIENT.add_update(data, user)
        return make_api_response({'success': True, "op": op, 'hash': qhash})
    except PermissionError as e:
        return make_api_response(None, str(e), 403)
    except (ValueError, InvalidSafehash) as e:
        return make_api_response(None, str(e), 400)


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

    try:
        return make_api_response(CLIENT.add_update_many(data))
    except PermissionError as e:
        return make_api_response(None, str(e), 403)
    except (ValueError, InvalidSafehash) as e:
        return make_api_response(None, str(e), 400)


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
