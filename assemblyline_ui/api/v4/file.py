import concurrent.futures
import os
import re
import tempfile

from flask import request

from assemblyline.common import forge
from assemblyline.common.codec import encode_file
from assemblyline.common.dict_utils import unflatten
from assemblyline.common.hexdump import hexdump
from assemblyline.common.str_utils import safe_str
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint, stream_file_response
from assemblyline_ui.config import STORAGE, ALLOW_RAW_DOWNLOADS
from assemblyline_ui.helper.result import format_result
from assemblyline_ui.helper.user import load_user_settings

Classification = forge.get_classification()
config = forge.get_config()

FILTER_ASCII = b''.join([bytes([x]) if x in range(32, 127) or x in [9, 10, 13] else b'.' for x in range(256)])

SUB_API = 'file'
file_api = make_subapi_blueprint(SUB_API, api_version=4)
file_api._doc = "Perform operations on files"

API_MAX_SIZE = 10 * 1024 * 1024


def list_file_active_keys(sha256, access_control=None):
    query = f"id:{sha256}*"

    item_list = [x for x in STORAGE.result.stream_search(query, access_control=access_control, as_obj=False)]

    item_list.sort(key=lambda k: k["created"], reverse=True)

    active_found = []
    active_keys = []
    alternates = []
    for item in item_list:
        if item['response']['service_name'] not in active_found:
            active_keys.append(item['id'])
            active_found.append(item['response']['service_name'])
        else:
            alternates.append(item)

    return active_keys, alternates


def list_file_childrens(sha256, access_control=None):
    query = f'id:{sha256}* AND response.extracted.sha256:*'
    resp = STORAGE.result.grouped_search("response.service_name", query=query, fl='id',
                                         sort="created desc", access_control=access_control,
                                         as_obj=False)

    result_keys = [x['items'][0]['id'] for x in resp['items']]

    output = []
    processed_sha256 = []
    for r in STORAGE.result.multiget(result_keys, as_dictionary=False, as_obj=False):
        for extracted in r['response']['extracted']:
            if extracted['sha256'] not in processed_sha256:
                processed_sha256.append(extracted['sha256'])
                output.append({
                    'name': extracted['name'],
                    'sha256': extracted['sha256']
                })
    return output


def list_file_parents(sha256, access_control=None):
    query = f"response.extracted.sha256:{sha256}"
    processed_sha256 = []
    output = []

    response = STORAGE.result.search(query, fl='id', sort="created desc",
                                     access_control=access_control, as_obj=False, use_archive=True)
    for p in response['items']:
        key = p['id']
        sha256 = key[:64]
        if sha256 not in processed_sha256:
            output.append(key)
            processed_sha256.append(sha256)

        if len(processed_sha256) >= 10:
            break

    return output


@file_api.route("/ascii/<sha256>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_file_ascii(sha256, **kwargs):
    """
    Return the ascii values for a file where ascii chars are replaced by DOTs.

    Variables:
    sha256       => A resource locator for the file (sha256)

    Arguments:
    None

    Data Block:
    None

    Result example:
    <THE ASCII FILE>
    """

    user = kwargs['user']
    file_obj = STORAGE.file.get(sha256, as_obj=False)

    if file_obj['size'] > API_MAX_SIZE:
        return make_api_response({}, "This file is too big to be seen through this API.", 403)

    if not file_obj:
        return make_api_response({}, "The file was not found in the system.", 404)

    if user and Classification.is_accessible(user['classification'], file_obj['classification']):
        with forge.get_filestore() as f_transport:
            data = f_transport.get(sha256)

        if not data:
            return make_api_response({}, "This file was not found in the system.", 404)

        return make_api_response(data.translate(FILTER_ASCII).decode())
    else:
        return make_api_response({}, "You are not allowed to view this file.", 403)


@file_api.route("/download/<sha256>/", methods=["GET"])
@api_login(required_priv=['R'], check_xsrf_token=False)
def download_file(sha256, **kwargs):
    """
    Download the file using the default encoding method. This api
    will force the browser in download mode.

    Variables:
    sha256       => A resource locator for the file (sha256)

    Arguments (optional):
    encoding     => Type of encoding use for the resulting file
    name         => Name of the file to download
    sid          => Submission ID where the file is from

    Data Block:
    None

    API call example:
    /api/v4/file/download/123456...654321/

    Result example:
    <THE FILE BINARY ENCODED IN SPECIFIED FORMAT>
    """
    user = kwargs['user']
    file_obj = STORAGE.file.get(sha256, as_obj=False)

    if not file_obj:
        return make_api_response({}, "The file was not found in the system.", 404)

    if user and Classification.is_accessible(user['classification'], file_obj['classification']):
        params = load_user_settings(user)

        name = request.args.get('name', sha256) or sha256
        name = os.path.basename(name)
        name = safe_str(name)

        sid = request.args.get('sid', None) or None
        submission = {}
        submission_meta = {}
        if sid is not None:
            submission = STORAGE.submission.get(sid, as_obj=False)
            if submission is None:
                submission = {}
            hash_list = [submission.get('files', [])[0].get('sha256', None)]
            hash_list.extend([x[:64] for x in submission.get('errors', [])])
            hash_list.extend([x[:64] for x in submission.get('results', [])])

            if sha256 not in hash_list:
                return make_api_response({}, f"File {sha256} is not associated to submission {sid}.", 403)

            if Classification.is_accessible(user['classification'], submission['classification']):
                submission_meta.update(unflatten(submission['metadata']))

        if Classification.enforce:
            submission_classification = submission.get('classification', file_obj['classification'])
            submission_meta['classification'] = Classification.max_classification(submission_classification,
                                                                                  file_obj['classification'])

        encoding = request.args.get('encoding', params['download_encoding'])
        if encoding not in ['raw', 'cart']:
            return make_api_response({}, f"{encoding.upper()} is not in the valid encoding types: [raw, cart]", 403)

        if encoding == "raw" and not ALLOW_RAW_DOWNLOADS:
            return make_api_response({}, "RAW file download has been disabled by administrators.", 403)

        _, download_path = tempfile.mkstemp()
        try:
            with forge.get_filestore() as f_transport:
                downloaded_from = f_transport.download(sha256, download_path)

            if not downloaded_from:
                return make_api_response({}, "The file was not found in the system.", 404)

            if encoding == 'raw':
                target_path = download_path
            else:
                target_path, name = encode_file(download_path, name, submission_meta)

            try:
                return stream_file_response(open(target_path, 'rb'), name, os.path.getsize(target_path))
            finally:
                if target_path:
                    if os.path.exists(target_path):
                        os.unlink(target_path)
        finally:
            if download_path:
                if os.path.exists(download_path):
                    os.unlink(download_path)
    else:
        return make_api_response({}, "You are not allowed to download this file.", 403)


@file_api.route("/hex/<sha256>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_file_hex(sha256, **kwargs):
    """
    Returns the file hex representation

    Variables:
    sha256       => A resource locator for the file (sha256)

    Arguments:
    None

    Data Block:
    None

    API call example:
    /api/v4/file/hex/123456...654321/

    Result example:
    <THE FILE HEX REPRESENTATION>
    """
    user = kwargs['user']
    file_obj = STORAGE.file.get(sha256, as_obj=False)

    if not file_obj:
        return make_api_response({}, "The file was not found in the system.", 404)

    if file_obj['size'] > API_MAX_SIZE:
        return make_api_response({}, "This file is too big to be seen through this API.", 403)

    if user and Classification.is_accessible(user['classification'], file_obj['classification']):
        with forge.get_filestore() as f_transport:
            data = f_transport.get(sha256)

        if not data:
            return make_api_response({}, "This file was not found in the system.", 404)

        return make_api_response(hexdump(data))
    else:
        return make_api_response({}, "You are not allowed to view this file.", 403)


@file_api.route("/strings/<sha256>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_file_strings(sha256, **kwargs):
    """
    Return all strings in a given file

    Variables:
    sha256       => A resource locator for the file (sha256)

    Arguments:
    len       => Minimum length for a string

    Data Block:
    None

    Result example:
    <THE LIST OF STRINGS>
    """
    user = kwargs['user']
    hlen = request.args.get('len', "6")
    file_obj = STORAGE.file.get(sha256, as_obj=False)

    if file_obj['size'] > API_MAX_SIZE:
        return make_api_response({}, "This file is too big to be seen through this API.", 403)

    if not file_obj:
        return make_api_response({}, "The file was not found in the system.", 404)

    if user and Classification.is_accessible(user['classification'], file_obj['classification']):
        with forge.get_filestore() as f_transport:
            data = f_transport.get(sha256)

        if not data:
            return make_api_response({}, "This file was not found in the system.", 404)

        # Ascii strings (we use decode with replace on to create delimiters)
        pattern = "[\x1f-\x7e]{%s,}" % hlen
        string_list = re.findall(pattern, data.decode("ascii", errors="replace"))

        # UTF-16 strings
        string_list += re.findall(pattern, data.decode("utf-16", errors="replace"))

        return make_api_response("\n".join(string_list))
    else:
        return make_api_response({}, "You are not allowed to view this file.", 403)


@file_api.route("/children/<sha256>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_file_children(sha256, **kwargs):
    """
    Get the list of children files for a given file

    Variables:
    sha256       => A resource locator for the file (sha256)

    Arguments:
    None

    Data Block:
    None

    API call example:
    /api/v4/file/children/123456...654321/

    Result example:
    [                           # List of children
     {"name": "NAME OF FILE",       # Name of the children
      "sha256": "123..DEF"},           # sha256 of the children
    ]
    """
    user = kwargs['user']
    file_obj = STORAGE.file.get(sha256, as_obj=False)

    if file_obj:
        if user and Classification.is_accessible(user['classification'], file_obj['classification']):
            output = []
            response = STORAGE.result.grouped_search("response.service_name",
                                                     query=f"id:{sha256}* AND response.extracted:*", fl="id", rows=100,
                                                     sort="created desc", access_control=user['access_control'],
                                                     as_obj=False)
            result_res = [x['id'] for y in response['items'] for x in y['items']]

            processed_srl = []
            for r in STORAGE.result.multiget(result_res, as_dictionary=False, as_obj=False):
                for extracted in r['response']['extracted']:
                    if extracted['sha256'] not in processed_srl:
                        processed_srl.append(extracted['sha256'])
                        output.append({'sha256': extracted['sha256'], 'name': extracted['name']})

            return make_api_response(output)
        else:
            return make_api_response({}, "You are not allowed to view this file.", 403)
    else:
        return make_api_response({}, "This file does not exists.", 404)


@file_api.route("/info/<sha256>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_file_information(sha256, **kwargs):
    """
    Get information about the file like:
        Hashes, size, frequency count, etc...

    Variables:
    sha256       => A resource locator for the file (sha256)

    Arguments:
    None

    Data Block:
    None

    API call example:
    /api/v4/file/info/123456...654321/

    Result example:
    {                                           # File information block
     "ascii": "PK..",                               # First 64 bytes as ASCII
     "classification": "UNRESTRICTED",              # Access control for the file
     "entropy": 7.99,                               # File's entropy
     "hex": "504b...c0b2",                          # First 64 bytes as hex
     "magic": "Zip archive data",                   # File's identification description (from magic)
     "md5": "8f31...a048",                          # File's MD5 hash
     "mime": "application/zip",                     # Mimetype of the file (from magic)
     "seen_count": 7,                               # Number of time we've seen this file
     "seen_first": "2015-03-04T21:59:13.204861Z",   # Time at which we first seen this file
     "seen_last": "2015-03-10T19:42:04.587233Z",    # Last time we've seen the file
     "sha256": "e021...4de2",                       # File's sha256 hash
     "sha1": "354f...fdab",                         # File's sha1 hash
     "size": 3417,                                  # Size of the file
     "ssdeep": "4:Smm...OHY+",                      # File's SSDEEP hash
     "tag": "archive/zip"                           # Type of file that we identified
    }
    """
    user = kwargs['user']
    file_obj = STORAGE.file.get(sha256, as_obj=False)

    if file_obj:
        if user and Classification.is_accessible(user['classification'], file_obj['classification']):
            return make_api_response(file_obj)
        else:
            return make_api_response({}, "You are not allowed to view this file.", 403)
    else:
        return make_api_response({}, "This file does not exists.", 404)


@file_api.route("/result/<sha256>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_file_results(sha256, **kwargs):
    """
    Get the all the file results of a specific file.

    Variables:
    sha256         => A resource locator for the file (SHA256)

    Arguments:
    None

    Data Block:
    None

    API call example:
    /api/v4/file/result/123456...654321/

    Result example:
    {"file_info": {},            # File info Block
     "results": {},              # Full result list
     "errors": {},               # Full error list
     "parents": {},              # List of possible parents
     "childrens": {},            # List of children files
     "tags": {},                 # List tags generated
     "metadata": {},             # Metadata facets results
     "file_viewer_only": True }  # UI switch to disable features
    """
    user = kwargs['user']
    file_obj = STORAGE.file.get(sha256, as_obj=False)

    if not file_obj:
        return make_api_response({}, "This file does not exists", 404)

    if user and Classification.is_accessible(user['classification'], file_obj['classification']):
        max_c12n = file_obj['classification']
        output = {
            "file_info": file_obj,
            "results": [],
            "tags": {},
            "attack_matrix": {},
            'heuristics': {},
            "signatures": set()
        }

        with concurrent.futures.ThreadPoolExecutor(4) as executor:
            res_ac = executor.submit(list_file_active_keys, sha256, user["access_control"])
            res_parents = executor.submit(list_file_parents, sha256, user["access_control"])
            res_children = executor.submit(list_file_childrens, sha256, user["access_control"])
            res_meta = executor.submit(STORAGE.get_file_submission_meta, sha256,
                                       config.ui.statistics.submission, user["access_control"])

        active_keys, alternates = res_ac.result()
        output['parents'] = res_parents.result()
        output['childrens'] = res_children.result()
        output['metadata'] = res_meta.result()

        output['results'] = []
        output['alternates'] = {}
        res = STORAGE.result.multiget(active_keys, as_dictionary=False, as_obj=False)
        for r in res:
            res = format_result(user['classification'], r, file_obj['classification'], build_hierarchy=True)
            if res:
                max_c12n = Classification.max_classification(max_c12n, res['classification'])
                output['results'].append(res)

        for i in alternates:
            if i['response']['service_name'] not in output["alternates"]:
                output["alternates"][i['response']['service_name']] = []
            i['response']['service_version'] = i['id'].split(".", 3)[2].replace("_", ".")
            output["alternates"][i['response']['service_name']].append(i)

        output['errors'] = []
        output['file_viewer_only'] = True

        for res in output['results']:
            for sec in res['result']['sections']:
                h_type = "info"

                if sec.get('heuristic', False):
                    # Get the heuristics data
                    if sec['heuristic']['score'] < 100:
                        h_type = "info"
                    elif sec['heuristic']['score'] < 1000:
                        h_type = "suspicious"
                    else:
                        h_type = "malicious"

                    item = (sec['heuristic']['heur_id'], sec['heuristic']['name'])
                    output['heuristics'].setdefault(h_type, [])
                    if item not in output['heuristics'][h_type]:
                        output['heuristics'][h_type].append(item)

                    # Process Attack matrix
                    for attack in sec['heuristic'].get('attack', []):
                        attack_id = attack['attack_id']
                        for cat in attack['categories']:
                            output['attack_matrix'].setdefault(cat, [])
                            item = (attack_id, attack['pattern'], h_type)
                            if item not in output['attack_matrix'][cat]:
                                output['attack_matrix'][cat].append(item)

                    # Process Signatures
                    for signature in sec['heuristic'].get('signature', []):
                        sig = (signature['name'], h_type)
                        if sig not in output['signatures']:
                            output['signatures'].add(sig)

                # Process tags
                for t in sec['tags']:
                    output["tags"].setdefault(t['type'], [])
                    t_item = (t['value'], h_type)
                    if t_item not in output["tags"][t['type']]:
                        output["tags"][t['type']].append(t_item)

        output['signatures'] = list(output['signatures'])

        output['file_info']['classification'] = max_c12n
        return make_api_response(output)
    else:
        return make_api_response({}, "You are not allowed to view this file", 403)


@file_api.route("/result/<sha256>/<service>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_file_results_for_service(sha256, service, **kwargs):
    """
    Get the all the file results of a specific file and a specific query.

    Variables:
    sha256         => A resource locator for the file (SHA256)

    Arguments:
    all         => if all argument is present, it will return all versions
                    NOTE: Max to 100 results...

    Data Block:
    None

    API call example:
    /api/v4/file/result/123456...654321/service_name/

    Result example:
    {"file_info": {},            # File info Block
     "results": {}}              # Full result list for the service
    """
    user = kwargs['user']
    file_obj = STORAGE.file.get(sha256, as_obj=False)

    args = [("fl", "_yz_rk"),
            ("sort", "created desc")]
    if "all" in request.args:
        args.append(("rows", "100"))
    else:
        args.append(("rows", "1"))

    if not file_obj:
        return make_api_response([], "This file does not exists", 404)

    if user and Classification.is_accessible(user['classification'], file_obj['classification']):
        res = STORAGE.result.search(f"id:{sha256}.{service}*", sort="created desc", fl="id",
                                    rows=100 if "all" in request.args else 1,
                                    access_control=user["access_control"], as_obj=False, use_archive=True)
        keys = [k["id"] for k in res['items']]

        results = []
        for r in STORAGE.result.multiget(keys, as_dictionary=False, as_obj=False):
            result = format_result(user['classification'], r, file_obj['classification'])
            if result:
                results.append(result)

        return make_api_response({"file_info": file_obj, "results": results})
    else:
        return make_api_response([], "You are not allowed to view this file", 403)


@file_api.route("/score/<sha256>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_file_score(sha256, **kwargs):
    """
    Get the score of the latest service run for a given file.

    Variables:
    sha256         => A resource locator for the file (SHA256)

    Arguments:
    None

    Data Block:
    None

    API call example:
    /api/v4/file/score/123456...654321/

    Result example:
    {"file_info": {},            # File info Block
     "result_keys": [<keys>]     # List of keys used to compute the score
     "score": 0}                 # Latest score for the file
    """
    user = kwargs['user']
    file_obj = STORAGE.file.get(sha256, as_obj=False)

    if not file_obj:
        return make_api_response([], "This file does not exists", 404)

    if user and Classification.is_accessible(user['classification'], file_obj['classification']):
        score = 0
        keys = []
        res = STORAGE.result.grouped_search("response.service_name", f"id:{sha256}*", fl="result.score,id",
                                            sort="created desc", access_control=user["access_control"],
                                            rows=100, as_obj=False)
        for s in res['items']:
            for d in s['items']:
                score += d['result']['score']
                keys.append(d["id"])

        return make_api_response({"file_info": file_obj, "score": score, "result_keys": keys})
    else:
        return make_api_response([], "You are not allowed to view this file", 403)
