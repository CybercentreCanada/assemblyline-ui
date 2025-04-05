from assemblyline.odm.models.user import ROLES
from assemblyline_ui.config import STORAGE


def get_collection(index, user):
    return INDEX_MAP.get(index, ADMIN_INDEX_MAP.get(index, None) if ROLES.administration in user['roles'] else None)


def get_default_sort(index, user):
    return INDEX_ORDER_MAP.get(index, ADMIN_INDEX_ORDER_MAP.get(index, None)
                               if ROLES.administration in user['roles'] else None)


def has_access_control(index):
    return index in INDEX_MAP


ADMIN_INDEX_MAP = {
    "apikey": STORAGE.apikey,
    'emptyresult': STORAGE.emptyresult,
    'error': STORAGE.error,
    'user': STORAGE.user
}

ADMIN_INDEX_ORDER_MAP = {
    'emptyresult': 'expiry_ts asc',
    'error': 'created desc',
    'user': 'id asc'
}

INDEX_MAP = {
    'alert': STORAGE.alert,
    'badlist': STORAGE.badlist,
    'file': STORAGE.file,
    'heuristic': STORAGE.heuristic,
    'result': STORAGE.result,
    'signature': STORAGE.signature,
    'submission': STORAGE.submission,
    'safelist': STORAGE.safelist,
    'workflow': STORAGE.workflow,
    'retrohunt': STORAGE.retrohunt,
}

INDEX_ORDER_MAP = {
    'alert': "reporting_ts desc",
    'badlist': "added desc",
    'file': "seen.last desc",
    'heuristic': "heur_id asc",
    'result': "created desc",
    'signature': "type asc",
    'submission': "times.submitted desc",
    'safelist': "added desc",
    'workflow': "last_seen desc",
    'retrohunt': "created_time desc",
}


def list_all_fields(user=None):
    fields_map = {k: INDEX_MAP[k].fields() for k in INDEX_MAP.keys()}

    if user and user['is_admin']:
        fields_map.update({k: ADMIN_INDEX_MAP[k].fields() for k in ADMIN_INDEX_MAP.keys()})

    return fields_map
