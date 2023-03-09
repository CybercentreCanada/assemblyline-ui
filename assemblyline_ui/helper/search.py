from assemblyline.odm.models.user import ROLES
from assemblyline_ui.config import STORAGE


def get_collection(bucket, user):
    return BUCKET_MAP.get(bucket, ADMIN_BUCKET_MAP.get(bucket, None) if ROLES.administration in user['roles'] else None)


def get_default_sort(bucket, user):
    return BUCKET_ORDER_MAP.get(bucket, ADMIN_BUCKET_ORDER_MAP.get(bucket, None)
                                if ROLES.administration in user['roles'] else None)


def has_access_control(bucket):
    return bucket in BUCKET_MAP


ADMIN_BUCKET_MAP = {
    'emptyresult': STORAGE.emptyresult,
    'error': STORAGE.error,
    'user': STORAGE.user
}

ADMIN_BUCKET_ORDER_MAP = {
    'emptyresult': 'expiry_ts asc',
    'error': 'created desc',
    'user': 'id asc'
}

BUCKET_MAP = {
    'alert': STORAGE.alert,
    'file': STORAGE.file,
    'heuristic': STORAGE.heuristic,
    'result': STORAGE.result,
    'signature': STORAGE.signature,
    'submission': STORAGE.submission,
    'safelist': STORAGE.safelist,
    'workflow': STORAGE.workflow,
    'retrohunt': STORAGE.retrohunt,
}

BUCKET_ORDER_MAP = {
    'alert': "reporting_ts desc",
    'file': "seen.last desc",
    'heuristic': "heur_id asc",
    'result': "created desc",
    'signature': "type asc",
    'submission': "times.submitted desc",
    'safelist': "added desc",
    'workflow': "last_seen desc",
    'retrohunt': "created desc",
}


def list_all_fields(user=None):
    fields_map = {k: BUCKET_MAP[k].fields() for k in BUCKET_MAP.keys()}

    if user and user['is_admin']:
        fields_map.update({k: ADMIN_BUCKET_MAP[k].fields() for k in ADMIN_BUCKET_MAP.keys()})

    return fields_map
