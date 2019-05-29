import sys
import random

from assemblyline.common import forge
from assemblyline.odm.models.alert import Alert
from assemblyline.odm.models.heuristic import Heuristic
from assemblyline.odm.randomizer import random_model_obj, get_random_phrase

# noinspection PyUnresolvedReferences
from base import create_users, create_services, create_signatures, create_submission


class PrintLogger(object):
    def __init__(self, indent=""):
        self.indent = indent

    def info(self, msg):
        print(f"{self.indent}{msg}")

    def warn(self, msg):
        print(f"{self.indent}[W] {msg}")

    def error(self, msg):
        print(f"{self.indent}[E] {msg}")


def create_basic_data(log, ds=None):
    ds = ds or forge.get_datastore()
    if ds.user.search("id:*", rows=0)['total'] == 0:
        log.info("\nCreating user objects...")
        create_users(ds, log=log)
    else:
        log.info("\nUsers already exist, skipping...")

    if ds.service_delta.search("id:*", rows=0)['total'] == 0:
        log.info("\nCreating services...")
        create_services(ds, log=log)
    else:
        log.info("Services already exist, skipping...")

    if ds.signature.search("id:*", rows=0)['total'] == 0:
        log.info("\nImporting test signatures...")
        signatures = create_signatures()
        for s in signatures:
            log.info(f"\t{s}")
    else:
        log.info("Signatures already exist, skipping...")
        signatures = list(ds.signature.keys())

    if ds.heuristic.search("id:*", rows=0)['total'] == 0:
        log.info("\nCreating random heuristics...")
        for _ in range(40):
            h = random_model_obj(Heuristic)
            h.name = get_random_phrase()
            ds.heuristic.save(h.heur_id, h)
            log.info(f'\t{h.heur_id}')
    else:
        log.info("Heuristics already exist, skipping...")

    return signatures


def create_extra_data(log, signatures, ds=None, fs=None):
    ds = ds or forge.get_datastore()
    fs = fs or forge.get_filestore()

    log.info("\nCreating 10 Submissions...")
    submissions = []
    for x in range(10):
        s = create_submission(ds, fs, log=log)
        submissions.append(s)

    log.info("\nCreating 50 Alerts...")
    for x in range(50):
        submission = random.choice(submissions)
        a = random_model_obj(Alert)
        a.file.sha256 = submission.files[0].sha256
        a.sid = submission.sid
        a.owner = random.choice(['admin', 'user', 'other', None])
        ds.alert.save(a.alert_id, a)
        log.info(f"\t{a.alert_id}")


if __name__ == "__main__":
    datastore = forge.get_datastore()
    logger = PrintLogger()
    sigs = create_basic_data(logger, ds=datastore)
    if "full" in sys.argv:
        create_extra_data(logger, sigs, ds=datastore)

    logger.info("\nDone.")
