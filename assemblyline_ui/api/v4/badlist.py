
import hashlib
import re
from urllib.parse import unquote

from flask import request

from assemblyline.common.isotime import now_as_iso
from assemblyline.datastore.exceptions import VersionConflictException
from assemblyline.odm.models.user import ROLES
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import CLASSIFICATION, LOGGER, STORAGE
from assemblyline_core.badlist_client import BadlistClient, InvalidBadhash

SUB_API = 'badlist'
badlist_api = make_subapi_blueprint(SUB_API, api_version=4)
badlist_api._doc = "Perform operations on badlisted hashes"

ATTRIBUTION_TYPES = ['actor', 'campaign', 'category', 'exploit', 'implant', 'family', 'network']

CLIENT = BadlistClient(datastore=STORAGE)


@badlist_api.route("/", methods=["POST", "PUT"])
@api_login(audit=False, require_role=[ROLES.badlist_manage], allow_readonly=False)
def add_or_update_hash(**kwargs):
    """
    Add a hash in the badlist if it does not exist or update its list of sources if it does

    Arguments:
    None

    Data Block:
    {
     "classification": "TLP:C",    # Classification of the bad hash (Computed for the mix of sources) - Optional
     "enabled": true,              # Is the bad hash enabled or not
     "dtl": 0,                     # Days to live for the badlist item (0: forever)
     "attribution": {              # Attributions associated to the hash  (Optional section)
        "actor": [...],                 # Associated actors
        "campaign": [...],              # Associated campaign
        "category": [...],              # Associated category
        "exploit": [...],               # Associated exploit
        "implant": [...],               # Associated implant
        "family": [...],                # Associated family
        "network": [...]                # Associated network
      },
      "file": {                     # Information about the file  - Only used in file mode
       "name": ["file.txt"]            # Possible names for the file
       "size": 12345,                  # Size of the file
       "type": "document/text"},       # Type of the file
     },
     "hashes": {                   # Information about the bad hash - At least one hash required
       "md5": "123...321",             # MD5 of the bad hash
       "sha1": "1234...4321",          # SHA1 of the bad hash
       "sha256": "12345....54321",     # SHA256 of the bad hash
       "ssdeep": "12345....54321",     # SSDeep of the bad hash
       "tlsh": "12345....54321",       # TLSH of the bad hash
     "sources": [                  # List of sources for why the file is badlisted, dedupped on name - Required
       {"classification": "TLP:C",     # Classification of the source (default: TLP:C) - Optional
        "name": "NSRL",                # Name of external source or user who badlisted it - Required
        "reason": [                    # List of reasons why the source is badlisted - Required
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
         "type": "network.url",        # Type of tag
         "value": "google.ca"          # Value of the tag
     },
     "type": "tag"                # Type of badlist hash (tag or file)
    }

    Result example:
    {
     "success": true,         # Was the hash successfully added
     "op": "add",             # Was it added to the system or updated
     "hash": "1234...4321"    # Hash that was used to store the badlist item
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
    except (ValueError, InvalidBadhash) as e:
        return make_api_response(None, str(e), 400)


@badlist_api.route("/add_update_many/", methods=["POST", "PUT"])
@api_login(audit=False, allow_readonly=False, require_role=[ROLES.badlist_manage])
def add_update_many_hashes(**_):
    """
    Add or Update a list of the bad hashes

    Variables:
    None

    Arguments:
    None

    Data Block (REQUIRED):
    [                             # List of Bad hash blocks
     {
      "classification": "TLP:C",    # Classification of the bad hash (Computed for the mix of sources) - Optional
      "enabled": true,              # Is the bad hash enabled or not
      "dtl": 0,                     # Days to live for the badlist item (0: forever)
      "attribution": {              # Attributions associated to the hash  (Optional section)
        "actor": [...],                 # Associated actors
        "campaign": [...],              # Associated campaign
        "category": [...],              # Associated category
        "exploit": [...],               # Associated exploit
        "implant": [...],               # Associated implant
        "family": [...],                # Associated family
        "network": [...]                # Associated network
      },
      "file": {                     # Information about the file  - Only used in file mode
        "name": ["file.txt"]            # Possible names for the file
        "size": 12345,                  # Size of the file
        "type": "document/text"},       # Type of the file
      },
      "hashes": {                   # Information about the bad hash - At least one hash required
        "md5": "123...321",             # MD5 of the bad hash
        "sha1": "1234...4321",          # SHA1 of the bad hash
        "sha256": "12345....54321",     # SHA256 of the bad hash
       "ssdeep": "12345....54321",     # SSDeep of the bad hash
       "tlsh": "12345....54321",       # TLSH of the bad hash
      "sources": [                  # List of sources for why the file is badlisted, dedupped on name - Required
        {"classification": "TLP:C",     # Classification of the source (default: TLP:C) - Optional
         "name": "NSRL",                # Name of external source or user who badlisted it - Required
         "reason": [                    # List of reasons why the source is badlisted - Required
           "Found as test.txt on default windows 10 CD",
           "Found as install.txt on default windows XP CD"
         ],
          "type": "external"},          # Type or source (external or user) - Required
        {"classification": "TLP:C",
         "name": "admin",
         "reason": ["We've seen this file many times and it leads to False positives"],
         "type": "user"}
      ],
      "tag": {                      # Tag information  - Only used in tag mode
          "type": "network.url",        # Type of tag
          "value": "google.ca"          # Value of the tag
      },
      "type": "tag"                 # Type of badlist hash (tag or file)
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
    except (ValueError, InvalidBadhash) as e:
        return make_api_response(None, str(e), 400)


@badlist_api.route("/<qhash>/", methods=["GET"])
@api_login(require_role=[ROLES.badlist_view])
def check_hash_exists(qhash, **kwargs):
    """
    Check if a hash exists in the badlist.

    Variables:
    qhash       => Hash to check is exist (either md5, sha1, sha256, tlsh, or ssdeep)

    Arguments:
    None

    Data Block:
    None

    API call example:
    GET /api/v1/badlist/123456...654321/

    Result example:
    {
     "classification": "TLP:C",    # Classification of the bad hash (Computed for the mix of sources) - Optional
     "enabled": true,              # Is the bad hash enabled or not
     "attribution": {              # Attributions associated to the hash  (Optional section)
        "actor": [...],                 # Associated actors
        "campaign": [...],              # Associated campaign
        "category": [...],              # Associated category
        "exploit": [...],               # Associated exploit
        "implant": [...],               # Associated implant
        "family": [...],                # Associated family
        "network": [...]                # Associated network
      },
      "file": {                     # Information about the file  - Only used in file mode
       "name": ["file.txt"]            # Possible names for the file
       "size": 12345,                  # Size of the file
       "type": "document/text"},       # Type of the file
     },
     "hashes": {                   # Information about the bad hash - At least one hash required
       "md5": "123...321",             # MD5 hash of the bad hash
       "sha1": "1234...4321",          # SHA1 hash of the bad hash
       "sha256": "12345....54321",     # SHA256 of the bad hash
       "ssdeep": "12345....54321",     # SSDeep of the bad hash
       "tlsh": "12345....54321",       # TLSH of the bad hash
     "sources": [                  # List of sources for why the file is badlisted, dedupped on name - Required
       {"classification": "TLP:C",     # Classification of the source (default: TLP:C) - Optional
        "name": "NSRL",                # Name of external source or user who badlisted it - Required
        "reason": [                    # List of reasons why the source is badlisted - Required
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
     "type": "tag"                # Type of badlist hash (tag or file)
    }
    """
    badlist = STORAGE.badlist.get_if_exists(qhash, as_obj=False)
    if badlist and CLASSIFICATION.is_accessible(kwargs['user']['classification'], badlist['classification']):
        return make_api_response(badlist)

    return make_api_response(None, "The hash was not found in the badlist.", 404)


@badlist_api.route("/<tag_type>/<tag_value>/", methods=["GET"])
@api_login(require_role=[ROLES.badlist_view])
def check_tag_exists(tag_type, tag_value, **kwargs):
    """
    Check if a tag exists in the badlist.

    Variables:
    tag_type       => Type of tag to search for
    tag_value      => Value of the tag to search for

    Arguments:
    None

    Data Block:
    None

    API call example:
    GET /api/v1/badlist/network.static.ip/1.1.1.1/

    Result example:
    {
     "classification": "TLP:C",    # Classification of the bad hash (Computed for the mix of sources) - Optional
     "enabled": true,              # Is the bad hash enabled or not
     "hashes": {                   # Information about the bad hash
       "md5": "123...321",             # MD5 hash of the bad hash
       "sha1": "1234...4321",          # SHA1 hash of the bad hash
       "sha256": "12345....54321",     # SHA256 of the bad hash
     "sources": [                  # List of sources for why the file is badlisted, dedupped on name - Required
       {"classification": "TLP:C",     # Classification of the source (default: TLP:C) - Optional
        "name": "NSRL",                # Name of external source or user who badlisted it - Required
        "reason": [                    # List of reasons why the source is badlisted - Required
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
     "type": "tag"                # Type of badlist hash (tag or file)
    }
    """
    qhash = hashlib.sha256(f"{tag_type}: {unquote(tag_value)}".encode('utf8')).hexdigest()

    badlist = STORAGE.badlist.get_if_exists(qhash, as_obj=False)
    if badlist and CLASSIFICATION.is_accessible(kwargs['user']['classification'], badlist['classification']):
        return make_api_response(badlist)

    return make_api_response(None, "The hash was not found in the badlist.", 404)


@badlist_api.route("/tlsh/<qhash>/", methods=["GET"])
@api_login(require_role=[ROLES.badlist_view])
def find_similar_tlsh(qhash, **kwargs):
    """
    Check if a file exists with a similar tlsh.

    Variables:
    qhash       => TLSH hash to query for

    Arguments:
    None

    Data Block:
    None

    API call example:
    GET /api/v1/badlist/tlsh/123456...654321/

    Result example:
    [
      {
        "classification": "TLP:C",    # Classification of the bad hash (Computed for the mix of sources) - Optional
        "enabled": true,              # Is the bad hash enabled or not
        "attribution": {              # Attributions associated to the hash  (Optional section)
            "actor": [...],                 # Associated actors
            "campaign": [...],              # Associated campaign
            "category": [...],              # Associated category
            "exploit": [...],               # Associated exploit
            "implant": [...],               # Associated implant
            "family": [...],                # Associated family
            "network": [...]                # Associated network
        },
        "file": {                     # Information about the file  - Only used in file mode
        "name": ["file.txt"]            # Possible names for the file
        "size": 12345,                  # Size of the file
        "type": "document/text"},       # Type of the file
        },
        "hashes": {                   # Information about the bad hash - At least one hash required
        "md5": "123...321",             # MD5 hash of the bad hash
        "sha1": "1234...4321",          # SHA1 hash of the bad hash
        "sha256": "12345....54321",     # SHA256 of the bad hash
        "ssdeep": "12345....54321",     # SSDeep of the bad hash
        "tlsh": "12345....54321",       # TLSH of the bad hash
        "sources": [                  # List of sources for why the file is badlisted, dedupped on name - Required
        {"classification": "TLP:C",     # Classification of the source (default: TLP:C) - Optional
            "name": "NSRL",                # Name of external source or user who badlisted it - Required
            "reason": [                    # List of reasons why the source is badlisted - Required
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
        "type": "tag"                # Type of badlist hash (tag or file)
      },
    ...]
    """
    user = kwargs['user']
    return make_api_response(STORAGE.badlist.search(
        f"hashes.tlsh:{qhash}", fl="*", as_obj=False, access_control=user['access_control'])['items'])


@badlist_api.route("/ssdeep/<path:qhash>/", methods=["GET"])
@api_login(require_role=[ROLES.badlist_view])
def find_similar_ssdeep(qhash, **kwargs):
    """
    Check if a file exists with a similar ssdeep.

    Variables:
    qhash       => SSDEEP hash to query for

    Arguments:
    None

    Data Block:
    None

    API call example:
    GET /api/v1/badlist/ssdeep/123:ABCDEFG:ABDC/

    Result example:
    [
      {
        "classification": "TLP:C",    # Classification of the bad hash (Computed for the mix of sources) - Optional
        "enabled": true,              # Is the bad hash enabled or not
        "attribution": {              # Attributions associated to the hash  (Optional section)
            "actor": [...],                 # Associated actors
            "campaign": [...],              # Associated campaign
            "category": [...],              # Associated category
            "exploit": [...],               # Associated exploit
            "implant": [...],               # Associated implant
            "family": [...],                # Associated family
            "network": [...]                # Associated network
        },
        "file": {                     # Information about the file  - Only used in file mode
        "name": ["file.txt"]            # Possible names for the file
        "size": 12345,                  # Size of the file
        "type": "document/text"},       # Type of the file
        },
        "hashes": {                   # Information about the bad hash - At least one hash required
        "md5": "123...321",             # MD5 hash of the bad hash
        "sha1": "1234...4321",          # SHA1 hash of the bad hash
        "sha256": "12345....54321",     # SHA256 of the bad hash
        "ssdeep": "12345....54321",     # SSDeep of the bad hash
        "tlsh": "12345....54321",       # TLSH of the bad hash
        "sources": [                  # List of sources for why the file is badlisted, dedupped on name - Required
        {"classification": "TLP:C",     # Classification of the source (default: TLP:C) - Optional
            "name": "NSRL",                # Name of external source or user who badlisted it - Required
            "reason": [                    # List of reasons why the source is badlisted - Required
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
        "type": "tag"                # Type of badlist hash (tag or file)
      },
    ...]
    """
    user = kwargs['user']
    try:
        _, long, _ = qhash.replace('/', '\\/').split(":")
    except ValueError:
        return make_api_response(None, f"Invalid SSDEEP hash provided: {qhash}", 400)
    return make_api_response(STORAGE.badlist.search(
        f"hashes.ssdeep:{long}~", fl="*", access_control=user['access_control'],
        as_obj=False)['items'])


@badlist_api.route("/enable/<qhash>/", methods=["PUT"])
@api_login(allow_readonly=False, require_role=[ROLES.badlist_manage])
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

    return make_api_response({'success': STORAGE.badlist.update(
        qhash, [
            (STORAGE.badlist.UPDATE_SET, 'enabled', data),
            (STORAGE.badlist.UPDATE_SET, 'updated', now_as_iso()),
        ])})


@badlist_api.route("/expiry/<qhash>/", methods=["DELETE"])
@api_login(allow_readonly=False, require_role=[ROLES.badlist_manage])
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

    return make_api_response({'success': STORAGE.badlist.update(
        qhash, [
            (STORAGE.badlist.UPDATE_SET, 'expiry_ts', None),
            (STORAGE.badlist.UPDATE_SET, 'updated', now_as_iso())
        ])})


@badlist_api.route("/source/<qhash>/<source>/<stype>/", methods=["DELETE"])
@api_login(allow_readonly=False, require_role=[ROLES.badlist_manage])
def remove_source(qhash, source, stype, **kwargs):
    """
    Remove a source from the specified badlist item

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

    if (source != user['uname'] or stype != 'user') and ROLES.administration not in user['roles']:
        return make_api_response(
            None, "You are not allowed to remove this source from this badlist item", 403)

    while True:
        current_badlist, version = STORAGE.badlist.get_if_exists(qhash, as_obj=False, version=True)
        if not current_badlist:
            return make_api_response({}, "The badlist item your are trying to modify does not exists", 404)

        if not CLASSIFICATION.is_accessible(user['classification'], current_badlist['classification']):
            return make_api_response(
                None, "You are not allowed to remove sources from this badlist item", 403)

        if len(current_badlist['sources']) == 1:
            return make_api_response(
                None, "You are not allowed to remove the last source from this badlist item", 403)

        found = -1
        max_classification = CLASSIFICATION.UNRESTRICTED
        for (src_id, src) in enumerate(current_badlist['sources']):
            if src['name'] == source and src['type'] == stype:
                found = src_id
            else:
                max_classification = CLASSIFICATION.max_classification(
                    max_classification, src.get('classification', max_classification))
        current_badlist['classification'] = max_classification

        if found == -1:
            return make_api_response({}, "The specified source does not exist in the specified badlist item", 404)

        current_badlist['sources'].pop(found)
        current_badlist['updated'] = now_as_iso()

        try:
            return make_api_response({'success': STORAGE.badlist.save(qhash, current_badlist, version=version)})

        except VersionConflictException as vce:
            LOGGER.info(f"Retrying save or freshen due to version conflict: {str(vce)}")


@badlist_api.route("/classification/<qhash>/<source>/<stype>/", methods=["PUT"])
@api_login(allow_readonly=False, require_role=[ROLES.badlist_manage])
def set_classification(qhash, source, stype, **kwargs):
    """
    Change the classification of a badlist item source

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

    if not CLASSIFICATION.is_valid(classification):
        return make_api_response(None, f"Classification {classification} is not valid.", 400)

    if not CLASSIFICATION.is_accessible(user['classification'], classification):
        return make_api_response(None, "You cannot set a classification that you don't have access to", 403)

    if (source != user['uname'] or stype != 'user') and ROLES.administration not in user['roles']:
        return make_api_response(
            None, "You are not allowed to change the classification for this badlist item", 403)

    while True:
        current_badlist, version = STORAGE.badlist.get_if_exists(qhash, as_obj=False, version=True)
        if not current_badlist:
            return make_api_response({}, "The badlist item your are trying to modify does not exists", 404)

        if not CLASSIFICATION.is_accessible(user['classification'], current_badlist['classification']):
            return make_api_response(
                None, "You are not allowed to change the classification for this badlist item", 403)

        found = False
        max_classification = classification
        for src in current_badlist['sources']:
            if src['name'] == source and src['type'] == stype:
                found = True
                src['classification'] = classification

            max_classification = CLASSIFICATION.max_classification(
                max_classification, src.get('classification', max_classification))

        if not found:
            return make_api_response({}, "The specified source does not exist in the specified badlist item", 404)

        current_badlist['classification'] = max_classification
        current_badlist['updated'] = now_as_iso()

        try:
            return make_api_response({'success': STORAGE.badlist.save(qhash, current_badlist, version=version)})

        except VersionConflictException as vce:
            LOGGER.info(f"Retrying save or freshen due to version conflict: {str(vce)}")


@badlist_api.route("/expiry/<qhash>/", methods=["PUT"])
@api_login(allow_readonly=False, require_role=[ROLES.badlist_manage])
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

    if not re.match(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{6}Z', expiry):
        return make_api_response(
            None, "Invalid date format, must match ISO9660 format (0000-00-00T00:00:00.000000Z)", 400)

    return make_api_response({'success': STORAGE.badlist.update(
        qhash, [
            (STORAGE.badlist.UPDATE_SET, 'expiry_ts', expiry),
            (STORAGE.badlist.UPDATE_SET, 'updated', now_as_iso())
        ])})


@badlist_api.route("/attribution/<qhash>/<attrib_type>/<value>/", methods=["PUT"])
@api_login(allow_readonly=False, require_role=[ROLES.badlist_manage])
def add_attribution(qhash, attrib_type, value, **_):
    """
    Add an attribution to the coresponding hash

    Variables:
    qhash       => Hash to change
    attrib_type => Type of attribution to add
    value       => Value to add

    Arguments:
    None

    Data Block:
    None

    Result example:
    {"success": True}
    """

    if attrib_type not in ATTRIBUTION_TYPES:
        return make_api_response(None, f"Invalid attribution type, must in : {ATTRIBUTION_TYPES}", 400)

    while True:
        current_badlist, version = STORAGE.badlist.get_if_exists(qhash, as_obj=False, version=True)
        if not current_badlist:
            return make_api_response({}, "The badlist item your are trying to modify does not exists", 404)

        if current_badlist.get('attribution', None) is None:
            current_badlist['attribution'] = {attrib_type: [value]}
        elif current_badlist['attribution'].get(attrib_type, None) is None:
            current_badlist['attribution'][attrib_type] = [value]
        else:
            current_badlist['attribution'][attrib_type].append(value)
            current_badlist['attribution'][attrib_type] = list(set(current_badlist['attribution'][attrib_type]))

        current_badlist['updated'] = now_as_iso()
        try:
            return make_api_response({'success': STORAGE.badlist.save(qhash, current_badlist, version=version)})

        except VersionConflictException as vce:
            LOGGER.info(f"Retrying save or freshen due to version conflict: {str(vce)}")


@badlist_api.route("/attribution/<qhash>/<attrib_type>/<value>/", methods=["DELETE"])
@api_login(allow_readonly=False, require_role=[ROLES.badlist_manage])
def remove_attribution(qhash, attrib_type, value, **_):
    """
    Delete an attribution to the coresponding hash

    Variables:
    qhash       => Hash to change
    attrib_type => Type of attribution to delete
    value       => Value to delete

    Arguments:
    None

    Data Block:
    None

    Result example:
    {"success": True}
    """

    if attrib_type not in ATTRIBUTION_TYPES:
        return make_api_response(None, f"Invalid attribution type, must in : {ATTRIBUTION_TYPES}", 400)

    while True:
        current_badlist, version = STORAGE.badlist.get_if_exists(qhash, as_obj=False, version=True)
        if not current_badlist:
            return make_api_response({}, "The badlist ietm your are trying to modify does not exists", 404)

        if 'attribution' not in current_badlist:
            return make_api_response({'success': False})

        if attrib_type not in current_badlist['attribution']:
            return make_api_response({'success': False})

        current = set(current_badlist['attribution'][attrib_type])
        current_badlist['attribution'][attrib_type] = list(current.difference({value}))
        current_badlist['updated'] = now_as_iso()

        try:
            return make_api_response({'success': STORAGE.badlist.save(qhash, current_badlist, version=version)})

        except VersionConflictException as vce:
            LOGGER.info(f"Retrying save or freshen due to version conflict: {str(vce)}")


@badlist_api.route("/<qhash>/", methods=["DELETE"])
@api_login(allow_readonly=False, require_role=[ROLES.badlist_manage])
def delete_hash(qhash, **kwargs):
    """
    Delete a hash from the badlist

    Variables:
    qhash       => Hash to check

    Arguments:
    None

    Data Block:
    None

    API call example:
    DELETE /api/v1/badlist/123456...654321/

    Result example:
    {"success": True}
    """
    user = kwargs['user']

    if ROLES.administration in user['roles'] or ROLES.signature_manage in user['roles']:
        return make_api_response({'success': STORAGE.badlist.delete(qhash)})
    else:
        bad_hash = STORAGE.badlist.get_if_exists(qhash, as_obj=False)
        if bad_hash:
            bad_hash['sources'] = [x for x in bad_hash['sources'] if x['name'] != user['uname']]
            if len(bad_hash['sources']) == 0:
                return make_api_response({'success': STORAGE.badlist.delete(qhash)})
            else:
                return make_api_response({'success': STORAGE.badlist.save(qhash, bad_hash)})

        return make_api_response({'success': False})
