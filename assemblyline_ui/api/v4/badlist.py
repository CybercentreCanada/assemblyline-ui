
import hashlib
import re
from urllib.parse import unquote

from flask import request

from assemblyline.common.isotime import now_as_iso
from assemblyline.datastore.exceptions import VersionConflictException
from assemblyline.odm.models.user import ROLES
from assemblyline.remote.datatypes.lock import Lock
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import CLASSIFICATION, LOGGER, STORAGE, DEFAULT_BADLIST_TAG_EXPIRY

SUB_API = 'badlist'
badlist_api = make_subapi_blueprint(SUB_API, api_version=4)
badlist_api._doc = "Perform operations on badlisted hashes"

ATTRIBUTION_TYPES = ['actor', 'campaign', 'category', 'exploit', 'implant', 'family', 'network']


class InvalidBadhash(Exception):
    pass


def _merge_bad_hashes(new, old):
    try:
        # Check if hash types match
        if new['type'] != old['type']:
            raise InvalidBadhash(f"Bad hash type mismatch: {new['type']} != {old['type']}")

        # Use the new classification but we will recompute it later anyway
        old['classification'] = new['classification']

        # Update updated time
        old['updated'] = new.get('updated', now_as_iso())

        # Update hashes
        old['hashes'].update({k: v for k, v in new['hashes'].items() if v})

        # Merge attributions
        if not old['attribution']:
            old['attribution'] = new.get('attribution', None)
        elif new.get('attribution', None):
            for key in ["actor", 'campaign', 'category', 'exploit', 'implant', 'family', 'network']:
                old_value = old['attribution'].get(key, []) or []
                new_value = new['attribution'].get(key, []) or []
                old['attribution'][key] = list(set(old_value + new_value)) or None

        if old['attribution'] is not None:
            old['attribution'] = {key: value for key, value in old['attribution'].items() if value}

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
            raise InvalidBadhash("No valid source found")

        old_src_map = {x['name']: x for x in old['sources']}
        for name, src in src_map.items():
            if name not in old_src_map:
                old_src_map[name] = src
            else:
                old_src = old_src_map[name]
                if old_src['type'] != src['type']:
                    raise InvalidBadhash(f"Source {name} has a type conflict: {old_src['type']} != {src['type']}")

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
        raise InvalidBadhash(f"Invalid data provided: {str(e)}")


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

    # Set defaults
    data['classification'] = CLASSIFICATION.UNRESTRICTED
    data.setdefault('hashes', {})
    data.setdefault('expiry_ts', None)
    if data['type'] == 'tag':
        # Remove file related fields
        data.pop('file', None)
        data.pop('hashes', None)

        tag_data = data.get('tag', None)
        if tag_data is None or 'type' not in tag_data or 'value' not in tag_data:
            return make_api_response(None, "Tag data not found", 400)

        hashed_value = f"{tag_data['type']}: {tag_data['value']}".encode('utf8')
        data['hashes'] = {
            'md5': hashlib.md5(hashed_value).hexdigest(),
            'sha1': hashlib.sha1(hashed_value).hexdigest(),
            'sha256': hashlib.sha256(hashed_value).hexdigest()
        }

    elif data['type'] == 'file':
        data.pop('tag', None)
        data.setdefault('file', {})

    # Ensure expiry_ts is set on tag-related items
    dtl = data.pop('dtl', None) or DEFAULT_BADLIST_TAG_EXPIRY
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

    with Lock(f'add_or_update-badlist-{qhash}', 30):
        old = STORAGE.badlist.get_if_exists(qhash, as_obj=False)
        if old:
            try:
                # Save data to the DB
                STORAGE.badlist.save(qhash, _merge_bad_hashes(data, old))
                return make_api_response({'success': True, "op": "update", 'hash': qhash})
            except InvalidBadhash as e:
                return make_api_response({}, str(e), 400)
        else:
            try:
                data['sources'] = src_map.values()
                STORAGE.badlist.save(qhash, data)
                return make_api_response({'success': True, "op": "add", 'hash': qhash})
            except Exception as e:
                return make_api_response({}, f"Invalid data provided: {str(e)}", 400)


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
            hash_data['expiry_ts'] = hash_data.get('expiry_ts', now_as_iso(DEFAULT_BADLIST_TAG_EXPIRY))
        elif hash_data['type'] == 'file':
            hash_data.pop('tag', None)
            hash_data.setdefault('file', {})
        else:
            return make_api_response("", f"Invalid hash type: {hash_data['type']}", 400)

        # Ensure expiry_ts is set on tag-related items
        dtl = hash_data.pop('dtl', None) or DEFAULT_BADLIST_TAG_EXPIRY
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
    old_data = STORAGE.badlist.multiget(list(new_data.keys()), as_dictionary=True, as_obj=False,
                                        error_on_missing=False)

    # Test signature names
    plan = STORAGE.badlist.get_bulk_plan()
    for key, val in new_data.items():
        # Use maximum classification
        old_val = old_data.get(key, {'classification': CLASSIFICATION.UNRESTRICTED, 'attribution': {},
                                     'hashes': {}, 'sources': [], 'type': val['type']})

        # Add upsert operation
        try:
            plan.add_upsert_operation(key, _merge_bad_hashes(val, old_val))
        except InvalidBadhash as e:
            return make_api_response("", str(e), 400)

    if not plan.empty:
        # Execute plan
        res = STORAGE.badlist.bulk(plan)
        return make_api_response({"success": len(res['items']), "errors": res['errors']})

    return make_api_response({"success": 0, "errors": []})


@badlist_api.route("/<qhash>/", methods=["GET"])
@api_login(require_role=[ROLES.badlist_view])
def check_hash_exists(qhash, **kwargs):
    """
    Check if a hash exists in the badlist.

    Variables:
    qhash       => Hash to check is exist (either md5, sha1 or sha256)

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
    if len(qhash) not in [64, 40, 32]:
        return make_api_response(None, "Invalid hash length", 400)

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

    if len(qhash) not in [64, 40, 32]:
        return make_api_response(None, "Invalid hash length", 400)

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
    if len(qhash) not in [64, 40, 32]:
        return make_api_response(None, "Invalid hash length", 400)

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

    if len(qhash) not in [64, 40, 32]:
        return make_api_response(None, "Invalid hash length", 400)

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

    if len(qhash) not in [64, 40, 32]:
        return make_api_response(None, "Invalid hash length", 400)

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

    if len(qhash) not in [64, 40, 32]:
        return make_api_response(None, "Invalid hash length", 400)

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

    if len(qhash) not in [64, 40, 32]:
        return make_api_response(None, "Invalid hash length", 400)

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

    if len(qhash) not in [64, 40, 32]:
        return make_api_response(None, "Invalid hash length", 400)

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

    if len(qhash) not in [64, 40, 32]:
        return make_api_response(None, "Invalid hash length", 400)

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
