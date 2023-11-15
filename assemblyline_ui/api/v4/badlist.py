
import hashlib
from flask import request

from assemblyline.common.isotime import now_as_iso
from assemblyline.odm.models.user import ROLES
from assemblyline.remote.datatypes.lock import Lock
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import CLASSIFICATION, STORAGE

SUB_API = 'badlist'
badlist_api = make_subapi_blueprint(SUB_API, api_version=4)
badlist_api._doc = "Perform operations on badlisted hashes"


class InvalidBadhash(Exception):
    pass


def _merge_bad_hashes(new, old):
    try:
        # Check if hash types match
        if new['type'] != old['type']:
            raise InvalidBadhash(f"Bad hash type mismatch: {new['type']} != {old['type']}")

        # Use max classification
        old['classification'] = CLASSIFICATION.max_classification(old['classification'], new['classification'])

        # Update updated time
        old['updated'] = now_as_iso()

        # Update hashes
        old['hashes'].update(new['hashes'])

        # Merge attributions
        if not old['attribution']:
            old['attribution'] = new.get('attribution', None)
        elif new['attribution']:
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
            old['file'].update(new.get('file', {}))
        elif old['type'] == 'tag':
            old['tag'] = new['tag']

        # Merge sources
        src_map = {x['name']: x for x in new['sources']}
        if not src_map:
            raise InvalidBadhash("No valid source found")

        old_src_map = {x['name']: x for x in old['sources']}
        for name, src in src_map.items():
            old['classification'] = CLASSIFICATION.max_classification(
                old['classification'], src.get('classification', None))

            if name not in old_src_map:
                old_src_map[name] = src
            else:
                old_src = old_src_map[name]
                if old_src['type'] != src['type']:
                    raise InvalidBadhash(f"Source {name} has a type conflict: {old_src['type']} != {src['type']}")

                for reason in src['reason']:
                    if reason not in old_src['reason']:
                        old_src['reason'].append(reason)
        old['sources'] = old_src_map.values()
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
     "op": "add"              # Was it added to the system or updated
    }
    """
    # Load data
    data = request.json
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

    elif data['type'] == 'file':
        data.pop('tag', None)
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
                return make_api_response({'success': True, "op": "update"})
            except InvalidBadhash as e:
                return make_api_response({}, str(e), 400)
        else:
            try:
                data['sources'] = src_map.values()
                STORAGE.badlist.save(qhash, data)
                return make_api_response({'success': True, "op": "add"})
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
        if hash_data['type'] == 'tag':
            hash_data.pop('file', None)
        elif hash_data['type'] == 'file':
            hash_data.pop('tag', None)

        # Find the hash used for the key
        key = hash_data['hashes'].get('sha256', hash_data['hashes'].get('sha1', hash_data['hashes'].get('md5', None)))
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
        old_val = old_data.get(key, {'classification': CLASSIFICATION.UNRESTRICTED,
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

    if ROLES.administration in user['roles'] or ROLES.signature_manage in user['roles']:
        return make_api_response({'success': STORAGE.badlist.update(
            qhash, [(STORAGE.badlist.UPDATE_SET, 'enabled', data)])})

    return make_api_response({}, "You are not allowed to change the status", 403)


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
