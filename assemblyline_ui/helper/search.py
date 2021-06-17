from assemblyline_ui.config import STORAGE

BUCKET_MAP = {
    'alert': STORAGE.alert,
    'file': STORAGE.file,
    'heuristic': STORAGE.heuristic,
    'result': STORAGE.result,
    'signature': STORAGE.signature,
    'submission': STORAGE.submission,
    'safelist': STORAGE.safelist,
    'workflow': STORAGE.workflow
}

BUCKET_ORDER_MAP = {
    'alert': "reporting_ts desc",
    'file': "seen.last desc",
    'heuristic': "heur_id asc",
    'result': "created desc",
    'signature': "type asc",
    'submission': "times.submitted desc",
    'safelist': "added desc",
    'workflow': "last_seen desc"
}


def list_all_fields():
    return {k: BUCKET_MAP[k].fields() for k in BUCKET_MAP.keys()}
