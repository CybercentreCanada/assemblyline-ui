import base64
import os
import re
import subprocess
import tempfile

from flask import request

from assemblyline.common.codec import encode_file
from assemblyline.common.dict_utils import unflatten
from assemblyline.common.hexdump import dump, hexdump
from assemblyline.common.str_utils import safe_str
from assemblyline.common.threading import APMAwareThreadPoolExecutor
from assemblyline.datastore.collection import Index
from assemblyline.filestore import FileStoreException
from assemblyline.odm.models.user import ROLES
from assemblyline.odm.models.user_settings import ENCODINGS as FILE_DOWNLOAD_ENCODINGS
from assemblyline_ui.api.base import (
    api_login,
    make_api_response,
    make_subapi_blueprint,
    stream_file_response,
)
from assemblyline_ui.config import (
    AI_AGENT,
    ALLOW_RAW_DOWNLOADS,
    ALLOW_ZIP_DOWNLOADS,
    ARCHIVESTORE,
    CACHE,
    FILESTORE,
    STORAGE,
    config,
)
from assemblyline_ui.config import CLASSIFICATION as Classification
from assemblyline_ui.helper.ai.base import APIException, EmptyAIResponse
from assemblyline_ui.helper.result import format_result
from assemblyline_ui.helper.user import load_user_settings

LABEL_CATEGORIES = ['attribution', 'technique', 'info']
MAX_CONCURRENT_VECTORS = 5

FILTER_ASCII = b''.join([bytes([x]) if x in range(32, 127) or x in [9, 10, 13] else b'.' for x in range(256)])

SUB_API = 'file'
file_api = make_subapi_blueprint(SUB_API, api_version=4)
file_api._doc = "Perform operations on files"

API_MAX_SIZE = 1 * 1024 * 1024


@file_api.route("/ascii/<sha256>/", methods=["GET"])
@api_login(require_role=[ROLES.file_detail])
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
    {
      "content": <THE ASCII FILE>,
      "truncated": false
    }
    """

    user = kwargs['user']
    file_obj = STORAGE.file.get(sha256, as_obj=False)

    if not file_obj or not FILESTORE.exists(sha256):
        return make_api_response({}, "The file was not found in the system.", 404)

    if user and Classification.is_accessible(user['classification'], file_obj['classification']):
        try:
            data = FILESTORE.get(sha256)[:API_MAX_SIZE]
        except (FileStoreException, TypeError):
            data = None

        # Try to download from archive
        if not data and \
                ARCHIVESTORE is not None and \
                ARCHIVESTORE != FILESTORE and \
                ROLES.archive_download in user['roles'] and \
                ARCHIVESTORE.exists(sha256):
            try:
                data = ARCHIVESTORE.get(sha256)
            except FileStoreException:
                data = None

        if not data:
            return make_api_response({}, "This file was not found in the system.", 404)

        return make_api_response({
            "content": data.translate(FILTER_ASCII).decode(),
            "truncated": file_obj['size'] > API_MAX_SIZE
        })
    else:
        return make_api_response({}, "You are not allowed to view this file.", 403)


@file_api.route("/download/<sha256>/", methods=["GET"])
@api_login(check_xsrf_token=False, require_role=[ROLES.file_download])
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
        file_metadata = {}
        if sid is not None:
            submission = STORAGE.submission.get(sid, as_obj=False)
            if submission is None:
                submission = {}

            if Classification.is_accessible(user['classification'], submission['classification']):
                file_metadata.update(unflatten(submission['metadata']))

        if Classification.enforce:
            submission_classification = submission.get('classification', file_obj['classification'])
            file_metadata['classification'] = Classification.max_classification(submission_classification,
                                                                                file_obj['classification'])

        encoding = request.args.get('encoding', params['download_encoding'])
        password = request.args.get('password', params['default_zip_password'])

        if encoding not in FILE_DOWNLOAD_ENCODINGS:
            return make_api_response(
                {},
                f"{encoding.upper()} is not in the valid encoding types: {FILE_DOWNLOAD_ENCODINGS}", 403)

        if encoding == "raw" and not ALLOW_RAW_DOWNLOADS:
            return make_api_response({}, "RAW file download has been disabled by administrators.", 403)

        if encoding == "zip":
            if not ALLOW_ZIP_DOWNLOADS:
                return make_api_response({}, "PROTECTED file download has been disabled by administrators.", 403)
            elif not password:
                return make_api_response({}, "No password given or retrieved from user's settings.", 403)

        download_dir = None
        target_path = None

        # Create a temporary download location
        if encoding == 'zip':
            download_dir = tempfile.mkdtemp()
            download_path = os.path.join(download_dir, name)
        else:
            _, download_path = tempfile.mkstemp()

        try:
            try:
                downloaded_from = FILESTORE.download(sha256, download_path)
            except FileStoreException:
                downloaded_from = None

            # Try to download from archive
            if not downloaded_from and \
                    ARCHIVESTORE is not None and \
                    ARCHIVESTORE != FILESTORE and \
                    ROLES.archive_download in user['roles']:
                try:
                    downloaded_from = ARCHIVESTORE.download(sha256, download_path)
                except FileStoreException:
                    downloaded_from = None

            if not downloaded_from:
                return make_api_response({}, "The file was not found in the system.", 404)

            # Encode file
            if encoding == 'raw':
                target_path = download_path
            elif encoding == 'zip':
                name += '.zip'
                target_path = os.path.join(download_dir, name)
                subprocess.run(['zip', '-j', '--password', password, target_path, download_path], capture_output=True)
            else:
                target_path, name = encode_file(download_path, name, file_metadata)

            return stream_file_response(open(target_path, 'rb'), name, os.path.getsize(target_path))

        finally:
            # Cleanup
            if target_path:
                if os.path.exists(target_path):
                    os.unlink(target_path)
            if download_path:
                if os.path.exists(download_path):
                    os.unlink(download_path)
            if download_dir:
                if os.path.exists(download_dir):
                    os.rmdir(download_dir)
    else:
        return make_api_response({}, "You are not allowed to download this file.", 403)


@file_api.route("/filestore/<sha256>/", methods=["DELETE"])
@api_login(check_xsrf_token=True, require_role=[ROLES.file_purge])
def delete_file_from_filestore(sha256, **kwargs):
    """
    Delete a file from the filestore without deleting the file record

    Variables:
    sha256       => A resource locator for the file (sha256)

    Arguments:
    None

    Data Block:
    None

    API call example:
    DELETE /api/v4/file/filestore/123456...654321/

    Result example:
    {"success": True}
    """
    user = kwargs['user']
    file_obj = STORAGE.file.get(sha256, as_obj=False)

    if not file_obj:
        return make_api_response({}, "The file was not found in the system.", 404)

    if user and Classification.is_accessible(user['classification'], file_obj['classification']):
        FILESTORE.delete(sha256)
        return make_api_response({"success": True})
    else:
        return make_api_response({}, "You are not allowed to delete this file from the filestore.", 403)


@file_api.route("/ai/<sha256>/", methods=["GET"])
@api_login(require_role=[ROLES.file_detail])
def summarized_results(sha256, **kwargs):
    """
    Summarize AL results with AI for the given sha256

    Variables:
    sha256       => A resource locator for the file (sha256)

    Arguments:
    archive_only   => Only use the archive data to generate the summary
    no_cache       => Caching for the output of this API will be disabled
    with_trace     => Should the AI call return the full trace of the conversation?
    lang           => Which language do you want the AI to respond in?

    Data Block:
    None

    API call example:
    /api/v4/file/ai/123456...654321/

    Result example:
    {
      "content": <AI summary of the AL results>,
      "truncated": false
    }
    """
    if not AI_AGENT.has_backends():
        return make_api_response({}, "AI Support is disabled on this system.", 400)

    archive_only = request.args.get('archive_only', 'false').lower() in ['true', '']
    no_cache = request.args.get('no_cache', 'false').lower() in ['true', '']
    lang = request.args.get('lang', 'english')
    with_trace = request.args.get('with_trace', 'false').lower() in ['true', '']

    index_type = None
    if archive_only:
        if not config.datastore.archive.enabled:
            return make_api_response({}, "Archive Support is disabled on this system.", 400)
        index_type = Index.ARCHIVE

    user = kwargs['user']

    if archive_only and ROLES.archive_view not in user['roles']:
        return make_api_response({}, "User is not allowed to view the archive", 403)

    # Create the cache key
    cache_key = CACHE.create_key(sha256, user['classification'], index_type, archive_only, lang, with_trace, "file")
    ai_summary = None
    if (not no_cache):
        # Get the summary from cache
        ai_summary = CACHE.get(cache_key)

    if not ai_summary:
        data = STORAGE.get_ai_formatted_file_results_data(
            sha256, user_classification=user['classification'],
            user_access_control=user['access_control'], cl_engine=Classification, index_type=index_type)
        if data is None:
            return make_api_response("", "The file was not found in the system.", 404)

        try:
            ai_summary = AI_AGENT.summarized_al_submission(data, lang=lang, with_trace=with_trace)

            # Save to cache
            CACHE.set(cache_key, ai_summary)
        except (APIException, EmptyAIResponse) as e:
            return make_api_response("", str(e), 400)

    return make_api_response(ai_summary)


@file_api.route("/code_summary/<sha256>/", methods=["GET"])
@api_login(require_role=[ROLES.file_detail])
def summarize_code_snippet(sha256, **kwargs):
    """
    Summarize with AI the code at the given sha256
    If the file is not a code snippet, returns a 406 error code.

    Variables:
    sha256       => A resource locator for the file (sha256)

    Arguments:
    no_cache       => Caching for the output of this API will be disabled
    with_trace     => Should the AI call return the full trace of the conversation?
    lang           => Which language do you want the AI to respond in?

    Data Block:
    None

    API call example:
    /api/v4/file/code_summary/123456...654321/

    Result example:
    {
      "content": <AI summary of the code snippet>,
      "truncated": false
    }
    """
    if not AI_AGENT.has_backends():
        return make_api_response({}, "AI Support is disabled on this system.", 400)

    no_cache = request.args.get('no_cache', 'false').lower() in ['true', '']
    lang = request.args.get('lang', 'english')
    with_trace = request.args.get('with_trace', 'false').lower() in ['true', '']

    user = kwargs['user']

    # Create the cache key
    cache_key = CACHE.create_key(sha256, user['classification'], lang, with_trace, "code")
    ai_summary = None
    if (not no_cache):
        # Get the summary from cache
        ai_summary = CACHE.get(cache_key)

    if not ai_summary:
        file_obj = STORAGE.file.get(sha256, as_obj=False)

        if not file_obj:
            return make_api_response({}, "The file was not found in the system.", 404)

        if not file_obj['type'].startswith("code/"):
            return make_api_response({}, "This is not code, you cannot summarize it.", 406)

        # TODO: We should calculate the tokens here
        # if file_obj['size'] > API_MAX_SIZE:
        #     return make_api_response({}, "This file is too big to be seen through this API.", 403)

        if user and Classification.is_accessible(user['classification'], file_obj['classification']):
            try:
                data = FILESTORE.get(sha256)
            except (FileStoreException, TypeError):
                data = None

            # Try to download from archive
            if not data and \
                    ARCHIVESTORE is not None and \
                    ARCHIVESTORE != FILESTORE and \
                    ROLES.archive_download in user['roles'] and \
                    ARCHIVESTORE.exists(sha256):
                try:
                    data = ARCHIVESTORE.get(sha256)
                except FileStoreException:
                    data = None

            if not data:
                return make_api_response({}, "The file was not found in the system.", 404)

            try:
                ai_summary = AI_AGENT.summarize_code_snippet(data, lang=lang, with_trace=with_trace)

                # Save to cache
                CACHE.set(cache_key, ai_summary)
            except (APIException, EmptyAIResponse) as e:
                return make_api_response("", str(e), 400)
        else:
            return make_api_response({}, "You are not allowed to view this file.", 403)

    return make_api_response(ai_summary)


@file_api.route("/hex/<sha256>/", methods=["GET"])
@api_login(require_role=[ROLES.file_detail])
def get_file_hex(sha256, **kwargs):
    """
    Returns the file hex representation

    Variables:
    sha256       => A resource locator for the file (sha256)

    Arguments:
    bytes_only   => Only return bytes with no formatting
    length       => Number of bytes per lines

    Data Block:
    None

    API call example:
    /api/v4/file/hex/123456...654321/

    Result example:
    {
      "content": <THE FILE HEX REPRESENTATION>,
      "truncated": false
    }
    """
    user = kwargs['user']
    file_obj = STORAGE.file.get(sha256, as_obj=False)

    bytes_only = request.args.get('bytes_only', 'false').lower() in ['true', '']
    length = int(request.args.get('length', '16'))

    if not file_obj or not FILESTORE.exists(sha256):
        return make_api_response({}, "The file was not found in the system.", 404)

    if user and Classification.is_accessible(user['classification'], file_obj['classification']):
        try:
            data = FILESTORE.get(sha256)[:API_MAX_SIZE]
        except FileStoreException:
            data = None

        # Try to download from archive
        if not data and \
                ARCHIVESTORE is not None and \
                ARCHIVESTORE != FILESTORE and \
                ROLES.archive_download in user['roles'] and \
                ARCHIVESTORE.exists(sha256):
            try:
                data = ARCHIVESTORE.get(sha256)
            except FileStoreException:
                data = None

        if not data:
            return make_api_response({}, "This file was not found in the system.", 404)

        if bytes_only:
            return make_api_response({
                "content": dump(data).decode(),
                "truncated": file_obj['size'] > API_MAX_SIZE
            })
        else:
            return make_api_response({
                "content": hexdump(data, length=length),
                "truncated": file_obj['size'] > API_MAX_SIZE
            })
    else:
        return make_api_response({}, "You are not allowed to view this file.", 403)


@file_api.route("/image/<sha256>/", methods=["GET"])
@api_login(require_role=[ROLES.submission_view])
def get_file_image_datastream(sha256, **kwargs):
    """
    Returns the image file as a datastream

    Variables:
    sha256       => A resource locator for the file (sha256)

    Arguments:
    None

    Data Block:
    None

    API call example:
    /api/v4/file/image/123456...654321/

    Result example:
    data:image/png;base64,...
    """
    user = kwargs['user']
    file_obj = STORAGE.file.get(sha256, as_obj=False)

    if not file_obj:
        return make_api_response({}, "The file was not found in the system.", 404)

    if not file_obj.get('is_section_image', False) or not file_obj['type'].startswith("image/"):
        return make_api_response({}, "This file is not allowed to be downloaded as a datastream.", 403)

    if user and Classification.is_accessible(user['classification'], file_obj['classification']):
        try:
            data = FILESTORE.get(sha256)
        except (FileStoreException, TypeError):
            data = None

        # Try to download from archive
        if not data and \
                ARCHIVESTORE is not None and \
                ARCHIVESTORE != FILESTORE and \
                ROLES.archive_download in user['roles'] and \
                ARCHIVESTORE.exists(sha256):
            try:
                data = ARCHIVESTORE.get(sha256)
            except FileStoreException:
                data = None

        if not data:
            return make_api_response({}, "This file was not found in the system.", 404)

        return make_api_response(f"data:{file_obj['type']};base64,{base64.b64encode(data).decode()}")
    else:
        return make_api_response({}, "You are not allowed to view this file.", 403)


@file_api.route("/strings/<sha256>/", methods=["GET"])
@api_login(require_role=[ROLES.file_detail])
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
    {
      "content": <THE LIST OF STRINGS>,
      "truncated": false
    }
    """
    user = kwargs['user']
    hlen = request.args.get('len', "6")
    file_obj = STORAGE.file.get(sha256, as_obj=False)

    if not file_obj or not FILESTORE.exists(sha256):
        return make_api_response({}, "The file was not found in the system.", 404)

    if user and Classification.is_accessible(user['classification'], file_obj['classification']):
        try:
            data = FILESTORE.get(sha256)[:API_MAX_SIZE]
        except (FileStoreException, TypeError):
            data = None

        # Try to download from archive
        if not data and \
                ARCHIVESTORE is not None and \
                ARCHIVESTORE != FILESTORE and \
                ROLES.archive_download in user['roles'] and \
                ARCHIVESTORE.exists(sha256):
            try:
                data = ARCHIVESTORE.get(sha256)
            except FileStoreException:
                data = None

        if not data:
            return make_api_response({}, "This file was not found in the system.", 404)

        # Ascii strings (we use decode with replace on to create delimiters)
        pattern = "[\x20-\x7e]{%s,}" % hlen
        string_list = re.findall(pattern, data.decode("ascii", errors="replace"))

        # UTF-16 strings
        string_list += re.findall(pattern, data.decode("utf-16", errors="replace"))

        return make_api_response({
            "content": "\n".join(string_list),
            "truncated": file_obj['size'] > API_MAX_SIZE
        })
    else:
        return make_api_response({}, "You are not allowed to view this file.", 403)


@file_api.route("/children/<sha256>/", methods=["GET"])
@api_login(require_role=[ROLES.submission_view])
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
                                                     query=f"id:{sha256}* AND response.extracted:*", fl="*", rows=100,
                                                     sort="created desc", access_control=user['access_control'],
                                                     as_obj=False)

            processed_srl = []
            for r in response['items']:
                for extracted in r['items'][0]['response']['extracted']:
                    if extracted['sha256'] not in processed_srl:
                        processed_srl.append(extracted['sha256'])
                        output.append({'sha256': extracted['sha256'], 'name': extracted['name']})

            return make_api_response(output)
        else:
            return make_api_response({}, "You are not allowed to view this file.", 403)
    else:
        return make_api_response({}, "This file does not exists.", 404)


@file_api.route("/info/<sha256>/", methods=["GET"])
@api_login(require_role=[ROLES.submission_view, ROLES.file_detail])
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
@api_login(require_role=[ROLES.submission_view])
def get_file_results(sha256, **kwargs):
    """
    Get the all the file results of a specific file.

    Variables:
    sha256         => A resource locator for the file (SHA256)

    Optional Arguments:
    archive_only   =>   Only access the Malware archive (Default: False)

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

    if str(request.args.get('archive_only', 'false')).lower() in ['true', '']:
        index_type = Index.ARCHIVE
    else:
        index_type = None

    file_obj = STORAGE.file.get(sha256, as_obj=False, index_type=index_type)

    if not file_obj:
        return make_api_response({}, "This file does not exists", 404)

    if user and Classification.is_accessible(user['classification'], file_obj['classification']):
        max_c12n = file_obj['classification']
        output = {
            "classification": Classification.UNRESTRICTED,
            "file_info": file_obj,
            "results": [],
            "tags": {},
            "attack_matrix": {},
            'heuristics': {},
            "signatures": set()
        }

        with APMAwareThreadPoolExecutor(4) as executor:
            res_ac = executor.submit(STORAGE.list_file_active_keys, sha256,
                                     user["access_control"], index_type=index_type)
            res_parents = executor.submit(STORAGE.list_file_parents, sha256, user["access_control"])
            res_children = executor.submit(STORAGE.list_file_childrens, sha256, user["access_control"])
            res_meta = executor.submit(STORAGE.get_file_submission_meta, sha256,
                                       config.ui.statistics.submission, user["access_control"])

        active_keys, alternates = res_ac.result()
        output['parents'] = res_parents.result()
        output['childrens'] = res_children.result()
        output['metadata'] = res_meta.result()

        output['results'] = []
        output['alternates'] = {}
        res = STORAGE.result.multiget(active_keys, as_dictionary=False, as_obj=False, index_type=index_type)
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

        done_heuristics = set()
        for res in output['results']:
            sorted_sections = sorted(res.get('result', {}).get('sections', []),
                                     key=lambda i: i['heuristic']['score'] if i['heuristic'] is not None else 0,
                                     reverse=True)
            for sec in sorted_sections:
                h_type = "info"

                if sec.get('heuristic', False):
                    # Get the heuristics data
                    if sec['heuristic']['score'] >= config.submission.verdicts.malicious:
                        h_type = "malicious"
                    elif sec['heuristic']['score'] >= config.submission.verdicts.suspicious:
                        h_type = "suspicious"
                    elif sec['heuristic']['score'] >= config.submission.verdicts.info:
                        h_type = "info"
                    else:
                        h_type = "safe"

                    if sec['heuristic']['heur_id'] not in done_heuristics:
                        item = (sec['heuristic']['heur_id'], sec['heuristic']['name'])
                        output['heuristics'].setdefault(h_type, [])
                        output['heuristics'][h_type].append(item)
                        done_heuristics.add(sec['heuristic']['heur_id'])

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
                        sig = (signature['name'], h_type, signature.get('safe', False))
                        if sig not in output['signatures']:
                            output['signatures'].add(sig)

                # Process tags
                for t in sec['tags']:
                    output["tags"].setdefault(t['type'], [])
                    t_item = (t['value'], h_type, t['safelisted'], sec['classification'])
                    index = next((i for i, x in enumerate(output["tags"][t['type']])
                                  if x[0] == t_item[0] and x[1] == t_item[1]), None)

                    if index == None:
                        output["tags"][t['type']].append(t_item)
                    else:
                        existing = output["tags"][t['type']][index]
                        safelisted = t_item[2] or existing[2]
                        classification = Classification.min_classification(t_item[3], existing[3])
                        output["tags"][t['type']][index] = (t['value'], h_type, safelisted, classification)

        output['signatures'] = list(output['signatures'])

        output['classification'] = max_c12n
        return make_api_response(output)
    else:
        return make_api_response({}, "You are not allowed to view this file", 403)


@file_api.route("/result/<sha256>/<service>/", methods=["GET"])
@api_login(require_role=[ROLES.submission_view])
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

    if not file_obj:
        return make_api_response([], "This file does not exists", 404)

    if user and Classification.is_accessible(user['classification'], file_obj['classification']):
        res = STORAGE.result.search(f"id:{sha256}.{service}*", sort="created desc", fl="*",
                                    rows=100 if "all" in request.args else 1,
                                    access_control=user["access_control"], as_obj=False)

        results = []
        for r in res['items']:
            result = format_result(user['classification'], r, file_obj['classification'])
            if result:
                results.append(result)

        return make_api_response({"file_info": file_obj, "results": results})
    else:
        return make_api_response([], "You are not allowed to view this file", 403)


@file_api.route("/score/<sha256>/", methods=["GET"])
@api_login(require_role=[ROLES.submission_view])
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


@file_api.route("/similar/<sha256>/", methods=["GET", "POST"])
@api_login(require_role=[ROLES.submission_view])
def find_similar_files(sha256, **kwargs):
    """
    Find files related to the current files via TLSH, SSDEEP or Vectors

    Variables:
    sha256                  => A resource locator for the file (SHA256)

    Arguments:
    use_archive             => Also find similar file in archive
    archive_only            => Only find similar in the malware archive

    Data Block:
    None

    API call example:
    /api/v4/archive/similar/123456...654321/

    Result example:
    [   # List of files related
      {
            "items": []            # List of files hash
            "total": 201,          # Total files through this relation type
            "type": 'tlsh'         # Type of relationship used to finds thoses files
            "value": 'T123...123'  # Value used to do the relation
      },
      ...
    ]
    """
    user = kwargs['user']
    use_archive = request.args.get('use_archive', 'false').lower() in ['true', '']
    archive_only = request.args.get('archive_only', 'false').lower() in ['true', '']

    if (use_archive or archive_only) and ROLES.archive_view not in user['roles']:
        return make_api_response({}, "User is not allowed to view the archive", 403)

    if archive_only:
        index_type = Index.ARCHIVE
    elif use_archive:
        index_type = Index.HOT_AND_ARCHIVE
    else:
        index_type = Index.HOT

    file_obj = STORAGE.file.get_if_exists(sha256, as_obj=False, index_type=index_type)

    if not file_obj:
        return make_api_response({"success": False}, "This file does not exists", 404)

    if not user or not Classification.is_accessible(user['classification'], file_obj['classification']):
        return make_api_response({"success": False}, "You are not allowed to view this file", 403)

    def _do_search(data_type, value):
        if value:
            if data_type == "tlsh":
                query = f'tlsh:"{value}"'
            else:
                query = f'ssdeep:"{value}"~'

            res = STORAGE.file.search(query, rows=10, sort='seen.last desc', fl='type,sha256,seen.last',
                                      filters=[f'NOT(sha256:"{sha256}")'], access_control=user['access_control'],
                                      as_obj=False, index_type=index_type)
            if res['total'] > 0:
                # Remove unimportant fields
                res.pop('offset')
                res.pop('rows')

                # Add Type and value
                res['type'] = data_type
                res['value'] = value

                return [res]
        return []

    output = []

    # Look for similar TLSH and SSDEEPS
    tlsh = file_obj.get('tlsh', '')
    ssdeep = file_obj.get('ssdeep', '::').split(':')

    with APMAwareThreadPoolExecutor(3) as executor:
        tlsh_future = executor.submit(_do_search, 'tlsh', tlsh)
        ssdeep1_future = executor.submit(_do_search, 'ssdeep', ssdeep[1])
        ssdeep2_future = executor.submit(_do_search, 'ssdeep', ssdeep[2])

    # Adding outputs for all hashes
    output.extend(tlsh_future.result())
    output.extend(ssdeep1_future.result())
    output.extend(ssdeep2_future.result())

    # Find all possible vectors from this file
    vectors = set()
    for service_results in STORAGE.result.grouped_search('response.service_name',
                                                         rows=1000,
                                                         query=f'sha256:{sha256} AND result.sections.tags.vector:*',
                                                         fl="result.sections.tags.vector",
                                                         sort="created desc", as_obj=False,
                                                         index_type=index_type)['items']:
        for result in service_results['items']:
            for section in result['result']['sections']:
                vectors = vectors.union(set(section['tags']['vector'] if section['tags']['vector'] is not None else []))

    # Search for all vectors at the same time
    vector_futures = {}
    with APMAwareThreadPoolExecutor(MAX_CONCURRENT_VECTORS) as executor:
        for v in vectors:
            vector_futures[v] = executor.submit(
                STORAGE.result.grouped_search, 'sha256', rows=10,
                query=f'result.sections.tags.vector:"{v}"',
                filters=[f'NOT(sha256:"{sha256}")'],
                fl="type,sha256,created", sort="created desc",
                as_obj=False, access_control=user['access_control'], limit=1,
                index_type=index_type)

    # Gather and append vector results
    for k, v in vector_futures.items():
        res = v.result()
        if res['total'] > 0:
            # Flatten the grouped search results
            new_items = []
            for item_result in res['items']:
                new_items.extend(item_result['items'])
            res['items'] = new_items

            # Remove unimportant fields
            res.pop('offset')
            res.pop('rows')

            # Add Type and value
            res['type'] = 'vector'
            res['value'] = k

            output.append(res)

    return make_api_response(output)
