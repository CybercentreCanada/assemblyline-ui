
import concurrent.futures

from flask import request

from assemblyline.common.isotime import now_as_iso
from assemblyline.datastore.exceptions import SearchException
from assemblyline.odm.models.workflow import PRIORITIES, STATUSES
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import STORAGE, config, CLASSIFICATION as Classification

SUB_API = 'alert'

alert_api = make_subapi_blueprint(SUB_API, api_version=4)
alert_api._doc = "Perform operations on alerts"


def get_timming_filter(tc_start, tc):
    if tc:
        if tc_start:
            return f"reporting_ts:[{tc_start}{STORAGE.ds.DATE_FORMAT['SEPARATOR']}-{tc} TO {tc_start}]"
        else:
            return f"reporting_ts:[{STORAGE.ds.now}-{tc} TO {STORAGE.ds.now}]"
    elif tc_start:
        return f"reporting_ts:[* TO {tc_start}]"

    return None


def get_stats_for_fields(fields, query, tc_start, tc, access_control):
    if not tc_start and "no_delay" not in request.args and config.core.alerter.delay != 0:
        tc_start = now_as_iso(config.core.alerter.delay * -1)
    if tc and config.ui.read_only:
        tc += config.ui.read_only_offset
    timming_filter = get_timming_filter(tc_start, tc)

    filters = [x for x in request.args.getlist("fq") if x != ""]
    if timming_filter:
        filters.append(timming_filter)

    try:
        if isinstance(fields, list):
            with concurrent.futures.ThreadPoolExecutor(len(fields)) as executor:
                res = {field: executor.submit(STORAGE.alert.facet,
                                              field,
                                              query=query,
                                              filters=filters,
                                              limit=100,
                                              access_control=access_control)
                       for field in fields}

            return make_api_response({k: v.result() for k, v in res.items()})
        else:
            return make_api_response(STORAGE.alert.facet(fields, query=query, filters=filters,
                                                         limit=100, access_control=access_control))
    except SearchException as e:
        return make_api_response("", f"SearchException: {e}", 400)


@alert_api.route("/<alert_id>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_alert(alert_id, **kwargs):
    """
    Get the alert details for a given alert key

    Variables:
    alert_id         => ID of the alert to get the details for

    Arguments:
    None

    Data Block:
    None

    API call example:
    /api/v4/alert/1234567890/

    Result example:
    {
        KEY: VALUE,   # All fields of an alert in key/value pair
    }
    """
    user = kwargs['user']
    data = STORAGE.alert.get(alert_id, as_obj=False)

    if not data:
        return make_api_response("", "This alert does not exists...", 404)

    if user and Classification.is_accessible(user['classification'], data['classification']):
        return make_api_response(data)
    else:
        return make_api_response("", "You are not allowed to see this alert...", 403)


@alert_api.route("/statistics/", methods=["GET"])
@api_login()
def alerts_statistics(**kwargs):
    """
    Load facet statistics for the alerts matching the query.

    Variables:
    None

    Arguments:
    fq         => Post filter queries (you can have multiple of those)
    q          => Query to apply to the alert list
    tc_start   => Time offset at which we start the time constraint
    tc         => Time constraint applied to the API
    no_delay   => Do not delay alerts

    Data Block:
    None

    Result example:

    """
    user = kwargs['user']

    query = request.args.get('q', "alert_id:*") or "alert_id:*"
    tc_start = request.args.get('tc_start', None)
    tc = request.args.get('tc', None)
    alert_statistics_fields = config.ui.statistics.alert

    return get_stats_for_fields(alert_statistics_fields, query, tc_start, tc, user['access_control'])


@alert_api.route("/labels/", methods=["GET"])
@api_login()
def alerts_labels(**kwargs):
    """
    Run a facet search to find the different labels matching the query.

    Variables:
    None

    Arguments:
    fq         => Post filter queries (you can have multiple of those)
    q          => Query to apply to the alert list
    tc_start   => Time offset at which we start the time constraint
    tc         => Time constraint applied to the API
    no_delay   => Do not delay alerts

    Data Block:
    None

    Result example:

    """
    user = kwargs['user']

    query = request.args.get('q', "alert_id:*") or "alert_id:*"
    tc_start = request.args.get('tc_start', None)
    tc = request.args.get('tc', None)

    return get_stats_for_fields("label", query, tc_start, tc, user['access_control'])


@alert_api.route("/priorities/", methods=["GET"])
@api_login()
def alerts_priorities(**kwargs):
    """
    Run a facet search to find the different priorities matching the query.

    Variables:
    None

    Arguments:
    fq         => Post filter queries (you can have multiple of those)
    q          => Query to apply to the alert list
    tc_start   => Time offset at which we start the time constraint
    tc         => Time constraint applied to the API
    no_delay   => Do not delay alerts

    Data Block:
    None

    Result example:

    """
    user = kwargs['user']

    query = request.args.get('q', "alert_id:*") or "alert_id:*"
    tc_start = request.args.get('tc_start', None)
    tc = request.args.get('tc', None)

    return get_stats_for_fields("priority", query, tc_start, tc, user['access_control'])


@alert_api.route("/statuses/", methods=["GET"])
@api_login()
def alerts_statuses(**kwargs):
    """
    Run a facet search to find the different statuses matching the query.

    Variables:
    None

    Arguments:
    fq         => Post filter queries (you can have multiple of those)
    q          => Query to apply to the alert list
    tc_start   => Time offset at which we start the time constraint
    tc         => Time constraint applied to the API
    no_delay   => Do not delay alerts

    Data Block:
    None

    Result example:

    """
    user = kwargs['user']

    query = request.args.get('q', "alert_id:*") or "alert_id:*"
    tc_start = request.args.get('tc_start', None)
    tc = request.args.get('tc', None)

    return get_stats_for_fields("status", query, tc_start, tc, user['access_control'])


@alert_api.route("/list/", methods=["GET"])
@api_login(required_priv=['R'])
def list_alerts(**kwargs):
    """
    List all alert in the system (per page)

    Variables:
    None

    Arguments:
    fq                => Post filter queries (you can have multiple of those)
    q                 => Query to apply to the alert list
    no_delay          => Do not delay alerts
    offset            => Offset at which we start giving alerts
    rows              => Numbers of alerts to return
    tc_start          => Time offset at which we start the time constraint
    tc                => Time constraint applied to the API
    use_archive       => List alerts from archive as well (Default: False)
    track_total_hits  => Track the total number of item that match the query (Default: 10 000)

    Data Block:
    None

    API call example:
    /api/v4/alert/list/

    Result example:
    {"total": 201,                # Total alerts found
     "offset": 0,                 # Offset in the alert list
     "count": 100,                # Number of alerts returned
     "items": []                  # List of alert blocks
    }
    """
    user = kwargs['user']

    use_archive = request.args.get('use_archive', 'false').lower() in ['true', '']
    offset = int(request.args.get('offset', 0))
    rows = int(request.args.get('rows', 100))
    query = request.args.get('q', "alert_id:*") or "alert_id:*"
    tc_start = request.args.get('tc_start', None)
    if not tc_start and "no_delay" not in request.args and config.core.alerter.delay != 0:
        tc_start = now_as_iso(config.core.alerter.delay * -1)
    tc = request.args.get('tc', None)
    if tc and config.ui.read_only:
        tc += config.ui.read_only_offset
    timming_filter = get_timming_filter(tc_start, tc)
    track_total_hits = request.args.get('track_total_hits', False)

    filters = [x for x in request.args.getlist("fq") if x != ""]
    if timming_filter:
        filters.append(timming_filter)

    try:
        return make_api_response(STORAGE.alert.search(
            query, offset=offset, rows=rows, fl="*", sort="reporting_ts desc",
            access_control=user['access_control'],
            filters=filters, as_obj=False, use_archive=use_archive, track_total_hits=track_total_hits))
    except SearchException as e:
        return make_api_response("", f"SearchException: {e}", 400)


@alert_api.route("/grouped/<field>/", methods=["GET"])
@api_login(required_priv=['R'])
def list_grouped_alerts(field, **kwargs):
    """
    List all alert grouped by a given field

    Variables:
    None

    Arguments:
    fq                => Post filter queries (you can have multiple of those)
    q                 => Query to apply to the alert list
    no_delay          => Do not delay alerts
    offset            => Offset at which we start giving alerts
    rows              => Numbers of alerts to return
    tc_start          => Time offset at which we start the time constraint
    tc                => Time constraint applied to the API
    use_archive       => List alerts from archive as well (Default: False)
    track_total_hits  => Track the total number of item that match the query (Default: 10 000)

    Data Block:
    None

    API call example:
    /api/v4/alert/grouped/md5/

    Result example:
    {"total": 201,                # Total alerts found
     "counted_total": 123,        # Number of alert returned in the current call
     "offset": 0,                 # Offset in the alert list
     "rows": 100,                 # Number of alerts returned
     "items": [],                 # List of alert blocks
     "tc_start": "2015-05..."     # UTC timestamp for future query (ISO Format)
    }
    """
    def get_dict_item(parent, cur_item):
        if "." in cur_item:
            key, remainder = cur_item.split(".", 1)
            return get_dict_item(parent.get(key, {}), remainder)
        else:
            return parent[cur_item]

    user = kwargs['user']

    offset = int(request.args.get('offset', 0))
    rows = int(request.args.get('rows', 100))
    query = request.args.get('q', "alert_id:*") or "alert_id:*"
    tc_start = request.args.get('tc_start', None)
    track_total_hits = request.args.get('track_total_hits', False)
    use_archive = request.args.get('use_archive', 'false').lower() in ['true', '']

    if not tc_start:
        if "no_delay" not in request.args and config.core.alerter.delay != 0:
            tc_start = now_as_iso(config.core.alerter.delay * -1)
        else:
            tc_start = now_as_iso()

    tc = request.args.get('tc', None)
    if tc and config.ui.read_only:
        tc += config.ui.read_only_offset
    timming_filter = get_timming_filter(tc_start, tc)

    filters = [x for x in request.args.getlist("fq") if x != ""]
    if timming_filter:
        filters.append(timming_filter)
    filters.append(f"{field}:*")

    try:
        res = STORAGE.alert.grouped_search(field, query=query, offset=offset, rows=rows, sort="reporting_ts desc",
                                           group_sort="reporting_ts desc", access_control=user['access_control'],
                                           filters=filters, fl="*", as_obj=False,
                                           use_archive=use_archive, track_total_hits=track_total_hits)
        alerts = []
        hash_list = []
        hint_list = set()
        counted_total = 0

        # Loop through grouped alerts
        for item in res['items']:
            # Update total
            counted_total += item['total']

            # Gather the first alert sample, set it's group_count and add it to the alert list
            data = item['items'][0]
            data['group_count'] = item['total']
            alerts.append(data)

            # Gather a list of possible owner hints
            if field in ['file.md5', 'file.sha1', 'file.sha256'] and not data.get('owner', None):
                hash_list.append(get_dict_item(data, field))

        if hash_list:
            # Lookup owner of previous hashes
            hint_resp = STORAGE.alert.grouped_search(field, query=" OR ".join([f"{field}:{h}" for h in hash_list]),
                                                     fl=field, rows=rows, filters=["owner:*"],
                                                     access_control=user['access_control'], as_obj=False)
            for hint_item in hint_resp['items']:
                hint_list.add(hint_item['value'])

        for a in alerts:
            if get_dict_item(a, field) in hint_list:
                a['hint_owner'] = True
            else:
                a['hint_owner'] = False

        res['items'] = alerts
        res['tc_start'] = tc_start
        res['counted_total'] = counted_total
        return make_api_response(res)
    except SearchException as e:
        return make_api_response("", f"SearchException: {e}", 400)


@alert_api.route("/label/<alert_id>/", methods=["POST"])
@api_login(required_priv=['W'], allow_readonly=False)
def add_labels(alert_id, **kwargs):
    """
    Add one or multiple labels to a given alert

    Variables:
    alert_id           => ID of the alert to add the label to

    Arguments:
    None

    Data Block:
    ["LBL1", "LBL2"]   => List of labels to add as comma separated string

    API call example:
    /api/v4/alert/label/12345...67890/

    Result example:
    {"success": true}
    """
    user = kwargs['user']
    try:
        labels = set(request.json)
    except ValueError:
        return make_api_response({"success": False}, err="Invalid list of labels received.", status_code=400)

    alert = STORAGE.alert.get(alert_id, as_obj=False)

    if not alert:
        return make_api_response({"success": False}, err="Alert ID %s not found" % alert_id, status_code=404)

    if not Classification.is_accessible(user['classification'], alert['classification']):
        return make_api_response("", "You are not allowed to see this alert...", 403)

    cur_label = set(alert.get('label', []))
    label_diff = labels.difference(labels.intersection(cur_label))
    if label_diff:
        return make_api_response({
            "success": STORAGE.alert.update(alert_id, [(STORAGE.alert.UPDATE_APPEND, 'label', lbl)
                                                       for lbl in label_diff])})
    else:
        return make_api_response({"success": True})


@alert_api.route("/label/batch/", methods=["POST"])
@api_login(required_priv=['W'], allow_readonly=False)
def add_labels_by_batch(**kwargs):
    """
    Apply labels to all alerts matching the given filters

    Variables:
    None

    Arguments:
    q          =>  Main query to filter the data [REQUIRED]
    tc_start   => Time offset at which we start the time constraint
    tc         => Time constraint applied to the API
    fq         =>  Filter query applied to the data

    Data Block:
    ["LBL1", "LBL2"]   => List of labels to add as comma separated string

    API call example:
    /api/v4/alert/label/batch/?q=protocol:SMTP

    Result example:
    { "success": true }
    """
    user = kwargs['user']
    try:
        labels = set(request.json)
    except ValueError:
        return make_api_response({"success": False}, err="Invalid list of labels received.", status_code=400)

    query = request.args.get('q', "alert_id:*") or "alert_id:*"
    tc_start = request.args.get('tc_start', None)
    tc = request.args.get('tc', None)
    if tc and config.ui.read_only:
        tc += config.ui.read_only_offset
    timming_filter = get_timming_filter(tc_start, tc)

    filters = [x for x in request.args.getlist("fq") if x != ""]
    if timming_filter:
        filters.append(timming_filter)

    return make_api_response({
        "success": STORAGE.alert.update_by_query(query, [(STORAGE.alert.UPDATE_APPEND, 'label', lbl) for lbl in labels],
                                                 filters, access_control=user['access_control'])})


@alert_api.route("/priority/<alert_id>/", methods=["POST"])
@api_login(required_priv=['W'], allow_readonly=False)
def change_priority(alert_id, **kwargs):
    """
    Change the priority of a given alert

    Variables:
    alert_id      => ID of the alert to change the priority

    Arguments:
    "HIGH"        => New priority for the alert

    Data Block:
    None

    API call example:
    /api/v4/alert/priority/12345...67890/

    Result example:
    {"success": true}
    """
    user = kwargs['user']
    try:
        priority = request.json
        priority = priority.upper()
        if priority not in PRIORITIES:
            raise ValueError("Not in priorities")
    except ValueError:
        return make_api_response({"success": False}, err="Invalid priority received.", status_code=400)

    alert = STORAGE.alert.get(alert_id, as_obj=False)

    if not alert:
        return make_api_response({"success": False},
                                 err="Alert ID %s not found" % alert_id,
                                 status_code=404)

    if not Classification.is_accessible(user['classification'], alert['classification']):
        return make_api_response("", "You are not allowed to see this alert...", 403)

    if priority != alert.get('priority', None):
        return make_api_response({
            "success": STORAGE.alert.update(alert_id, [(STORAGE.alert.UPDATE_SET, 'priority', priority)])})
    else:
        return make_api_response({"success": True})


@alert_api.route("/priority/batch/", methods=["POST"])
@api_login(required_priv=['W'], allow_readonly=False)
def change_priority_by_batch(**kwargs):
    """
    Apply priority to all alerts matching the given filters

    Variables:
    None

    Arguments:
    q          =>  Main query to filter the data [REQUIRED]
    tc_start   => Time offset at which we start the time constraint
    tc         => Time constraint applied to the API
    fq         =>  Filter query applied to the data

    Data Block:
    "HIGH"         => New priority for the alert

    API call example:
    /api/v4/alert/priority/batch/?q=al_av:*

    Result example:
    {"success": true}
    """
    user = kwargs['user']
    try:
        priority = request.json
        priority = priority.upper()
        if priority not in PRIORITIES:
            raise ValueError("Not in priorities")
    except ValueError:
        return make_api_response({"success": False}, err="Invalid priority received.", status_code=400)

    query = request.args.get('q', "alert_id:*") or "alert_id:*"
    tc_start = request.args.get('tc_start', None)
    tc = request.args.get('tc', None)
    if tc and config.ui.read_only:
        tc += config.ui.read_only_offset
    timming_filter = get_timming_filter(tc_start, tc)

    filters = [x for x in request.args.getlist("fq") if x != ""]
    if timming_filter:
        filters.append(timming_filter)

    return make_api_response({
        "success": STORAGE.alert.update_by_query(query, [(STORAGE.alert.UPDATE_SET, 'priority', priority)],
                                                 filters, access_control=user['access_control'])})


@alert_api.route("/status/<alert_id>/", methods=["POST"])
@api_login(required_priv=['W'], allow_readonly=False)
def change_status(alert_id, **kwargs):
    """
    Change the status of a given alert

    Variables:
    alert_id       => ID of the alert to change the status

    Arguments:
    None

    Data Block:
    "MALICIOUS"      => New status for the alert

    API call example:
    /api/v4/alert/status/12345...67890/

    Result example:
    {"success": true}
    """
    user = kwargs['user']
    try:
        status = request.json
        status = status.upper()
        if status not in STATUSES:
            raise ValueError("Not in priorities")
    except ValueError:
        return make_api_response({"success": False}, err="Invalid status received.", status_code=400)

    alert = STORAGE.alert.get(alert_id, as_obj=False)

    if not alert:
        return make_api_response({"success": False},
                                 err="Alert ID %s not found" % alert_id,
                                 status_code=404)

    if not Classification.is_accessible(user['classification'], alert['classification']):
        return make_api_response("", "You are not allowed to see this alert...", 403)

    if status != alert.get('status', None):
        return make_api_response({
            "success": STORAGE.alert.update(alert_id, [(STORAGE.alert.UPDATE_SET, 'status', status)])})
    else:
        return make_api_response({"success": True})


@alert_api.route("/status/batch/", methods=["POST"])
@api_login(required_priv=['W'], allow_readonly=False)
def change_status_by_batch(**kwargs):
    """
    Apply status to all alerts matching the given filters

    Variables:
    status     =>  Status to apply

    Arguments:
    q          =>  Main query to filter the data [REQUIRED]
    tc_start   => Time offset at which we start the time constraint
    tc         => Time constraint applied to the API
    fq         =>  Filter query applied to the data

    Data Block:
    "MALICIOUS"      => New status for the alert

    API call example:
    /api/v4/alert/status/batch/MALICIOUS/?q=al_av:*

    Result example:
    {"success": true}
    """
    user = kwargs['user']
    try:
        status = request.json
        status = status.upper()
        if status not in STATUSES:
            raise ValueError("Not in priorities")
    except ValueError:
        return make_api_response({"success": False}, err="Invalid status received.", status_code=400)

    query = request.args.get('q', "alert_id:*") or "alert_id:*"
    tc_start = request.args.get('tc_start', None)
    tc = request.args.get('tc', None)
    if tc and config.ui.read_only:
        tc += config.ui.read_only_offset
    timming_filter = get_timming_filter(tc_start, tc)

    filters = [x for x in request.args.getlist("fq") if x != ""]
    if timming_filter:
        filters.append(timming_filter)

    return make_api_response({
        "success": STORAGE.alert.update_by_query(query, [(STORAGE.alert.UPDATE_SET, 'status', status)],
                                                 filters, access_control=user['access_control'])})


@alert_api.route("/ownership/<alert_id>/", methods=["GET"])
@api_login(required_priv=['W'], allow_readonly=False)
def take_ownership(alert_id, **kwargs):
    """
    Take ownership of a given alert

    Variables:
    alert_id    => ID of the alert to send to take ownership

    Arguments:
    None

    Data Block:
    None

    API call example:
    /api/v4/alert/ownership/12345...67890/

    Result example:
    {"success": true}
    """
    user = kwargs['user']

    alert = STORAGE.alert.get(alert_id, as_obj=False)

    if not alert:
        return make_api_response({"success": False},
                                 err="Alert ID %s not found" % alert_id,
                                 status_code=404)

    if not Classification.is_accessible(user['classification'], alert['classification']):
        return make_api_response({"success": False}, "You are not allowed to see this alert...", 403)

    current_owner = alert.get('owner', None)
    if current_owner is None:
        return make_api_response({
            "success": STORAGE.alert.update(alert_id, [(STORAGE.alert.UPDATE_SET, 'owner', user['uname'])])})
    else:
        return make_api_response({"success": False},
                                 err="Alert is already owned by %s" % current_owner,
                                 status_code=403)


@alert_api.route("/ownership/batch/", methods=["GET"])
@api_login(required_priv=['W'], allow_readonly=False)
def take_ownership_by_batch(**kwargs):
    """
    Take ownership of all alerts matching the given filters

    Variables:
    None

    Arguments:
    q          =>  Main query to filter the data [REQUIRED]
    tc_start   => Time offset at which we start the time constraint
    tc         => Time constraint applied to the API
    fq         =>  Filter query applied to the data

    Data Block:
    None

    API call example:
    /api/v4/alert/ownership/batch/?q=alert_id:7b*

    Result example:
    { "success": true }
    """
    user = kwargs['user']
    q = request.args.get('q', "alert_id:*") or "alert_id:*"
    tc_start = request.args.get('tc_start', None)
    tc = request.args.get('tc', None)
    if tc and config.ui.read_only:
        tc += config.ui.read_only_offset
    timming_filter = get_timming_filter(tc_start, tc)

    filters = [x for x in request.args.getlist("fq") if x != ""]
    if timming_filter:
        filters.append(timming_filter)
    filters.append("!owner:*")

    return make_api_response({
        "success": STORAGE.alert.update_by_query(q, [(STORAGE.alert.UPDATE_SET, 'owner', user['uname'])],
                                                 filters, access_control=user['access_control'])})


@alert_api.route("/related/", methods=["GET"])
@api_login()
def find_related_alert_ids(**kwargs):
    """
    Return the list of all IDs related to the currently selected query

    Variables:
    None

    Arguments:
    q         =>  Main query to filter the data [REQUIRED]
    tc        =>  Time constraint to apply to the search
    tc_start  =>  Time at which to start the days constraint
    fq        =>  Filter query applied to the data

    Data Block:
    None

    API call example:
    /api/v4/alert/related/?q=file.sha256:123456...ABCDEF

    Result example:
    ["1"]
    """
    user = kwargs['user']
    query = request.args.get('q', None)
    fq = request.args.getlist('fq')
    if not query and not fq:
        return make_api_response([], err="You need to at least provide a query to filter the data", status_code=400)

    if not query:
        query = fq.pop(0)
    tc = request.args.get('tc', None)
    if tc and config.ui.read_only:
        tc += config.ui.read_only_offset
    tc_start = request.args.get('tc_start', None)
    timming_filter = get_timming_filter(tc_start, tc)

    filters = [x for x in fq if x != ""]
    if timming_filter:
        filters.append(timming_filter)

    try:
        return make_api_response([x['alert_id'] for x in
                                  STORAGE.alert.stream_search(query, filters=filters, fl="alert_id",
                                                              access_control=user['access_control'], as_obj=False)])
    except SearchException as e:
        return make_api_response("", f"SearchException: {e}", 400)


@alert_api.route("/verdict/<alert_id>/<verdict>/", methods=["PUT"])
@api_login(audit=False, check_xsrf_token=False)
def set_verdict(alert_id, verdict, **kwargs):
    """
    Set the verdict of an alert based on its ID.

    Variables:
    submission_id   ->   ID of the alert to give a verdict to
    verdict         ->   verdict that the user think the alert is: malicious or non_malicious

    Arguments:
    None

    Data Block:
    None

    Result example:
    {"success": True}   # Has the verdict been set or not
    """
    reverse_verdict = {
        'malicious': 'non_malicious',
        'non_malicious': 'malicious'
    }

    user = kwargs['user']

    if verdict not in ['malicious', 'non_malicious']:
        return make_api_response({"success": False}, f"'{verdict}' is not a valid verdict.", 400)

    document = STORAGE.alert.get(alert_id, as_obj=False)

    if not document:
        return make_api_response({"success": False}, f"There are no alert with id: {alert_id}", 404)

    if not Classification.is_accessible(user['classification'], document['classification']):
        return make_api_response({"success": False}, "You are not allowed to give verdict on alert with "
                                                     f"ID: {alert_id}", 403)

    resp = STORAGE.alert.update_by_query(f"sid:{document['sid']}", [
        ('REMOVE', f'verdict.{verdict}', user['uname']),
        ('APPEND', f'verdict.{verdict}', user['uname']),
        ('REMOVE', f'verdict.{reverse_verdict[verdict]}', user['uname'])
    ])

    STORAGE.submission.update(document['sid'], [
        ('REMOVE', f'verdict.{verdict}', user['uname']),
        ('APPEND', f'verdict.{verdict}', user['uname']),
        ('REMOVE', f'verdict.{reverse_verdict[verdict]}', user['uname'])
    ])

    return make_api_response({"success": resp != 0})
