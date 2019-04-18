import sys
import random

from assemblyline.common import forge
from assemblyline.common.security import get_password_hash
from assemblyline.common.yara import YaraImporter
from assemblyline.odm.models.alert import Alert
from assemblyline.odm.models.emptyresult import EmptyResult
from assemblyline.odm.models.error import Error
from assemblyline.odm.models.file import File
from assemblyline.odm.models.heuristic import Heuristic
from assemblyline.odm.models.result import Result
from assemblyline.odm.models.service import Service
from assemblyline.odm.models.submission import Submission
from assemblyline.odm.models.user import User
from assemblyline.odm.models.user_settings import UserSettings
from assemblyline.odm.randomizer import random_model_obj, SERVICES, get_random_phrase


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
        log.info("\nCreating user object...")
        user_data = User({
            "agrees_with_tos": "NOW",
            "classification": "RESTRICTED",
            "name": "Admin user",
            "password": get_password_hash("admin"),
            "uname": "admin",
            "is_admin": True})
        ds.user.save('admin', user_data)
        ds.user_settings.save('admin', UserSettings())
        log.info(f"\tU:{user_data.uname}   P:{user_data.uname}")
        user_data = User({"name": "user", "password": get_password_hash("user"), "uname": "user"})
        ds.user.save('user', user_data)
        ds.user_settings.save('user', UserSettings())
        log.info(f"\tU:{user_data.uname}    P:{user_data.uname}")
    else:
        log.info("\nUsers already exist, skipping...")

    if ds.service_delta.search("id:*", rows=0)['total'] == 0:
        log.info("\nCreating services...")
        for svc_name, svc in SERVICES.items():
            service_data = Service({
                "name": svc_name,
                "enabled": True,
                "category": svc[0],
                "stage": svc[1],
                "version": "3.3.0"
            })
            # Save a v3 service
            ds.service.save(f"{service_data.name}_{service_data.version}", service_data)

            # Save the same service as v4
            service_data.version = "4.0.0"
            ds.service.save(f"{service_data.name}_{service_data.version}", service_data)

            # Save the default delta entry
            ds.service_delta.save(service_data.name, {"version": service_data.version})
            log.info(f'\t{svc_name}')
    else:
        log.info("Services already exist, skipping...")

    if ds.signature.search("id:*", rows=0)['total'] == 0:
        log.info("\nImporting test signatures...")
        yp = YaraImporter(logger=PrintLogger(indent="\t"))
        parsed = yp.parse_file('al_yara_signatures.yar')
        yp.import_now([p['rule'] for p in parsed])
        signatures = [p['rule']['name'] for p in parsed]
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

    log.info("\nCreating 20 Files...")
    file_hashes = []
    for x in range(20):
        f = random_model_obj(File)
        file_hashes.append(f.sha256)
        ds.file.save(f.sha256, f)

        fs.put(f.sha256, f.sha256)

        log.info(f"\t{f.sha256}")

    log.info("\nCreating 6 Results per file...")
    result_keys = []
    for fh in file_hashes:
        other_files = list(set(file_hashes) - {fh})

        for x in range(6):
            r = random_model_obj(Result)
            r.sha256 = fh

            for ext in r.response.extracted:
                ext.sha256 = random.choice(other_files)
                if fh == ext.sha256:
                    raise Exception("Invalid extracted file")

            for supp in r.response.supplementary:
                supp.sha256 = random.choice(other_files)
                if fh == supp.sha256:
                    raise Exception("Invalid supplementary file")

            for tag in r.result.tags:
                if random.randint(0,3) == 1:
                    tag.value = random.choice(signatures)
                    tag.type = "FILE_YARA_RULE"

            key = r.build_key()
            result_keys.append(key)
            ds.result.save(key, r)
            log.info(f"\t{key}")

    log.info("\nCreating 4 EmptyResults per file...")
    for fh in file_hashes:
        for x in range(4):
            # Get a random result key
            r = random_model_obj(Result)
            r.sha256 = fh
            key = f"{r.build_key()}.e"
            result_keys.append(key)

            # Save an empty result using that key
            ds.emptyresult.save(key, random_model_obj(EmptyResult))
            log.info(f"\t{key}")

    log.info("\nCreating 2 Errors per file...")
    error_keys = []
    for fh in file_hashes:
        for x in range(2):
            e = random_model_obj(Error)
            e.sha256 = fh
            key = e.build_key()
            error_keys.append(key)
            ds.error.save(key, e)
            log.info(f"\t{key}")

    log.info("\nCreating 10 Submissions...")
    submissions = []
    for x in range(10):
        s = random_model_obj(Submission)
        s.results = random.choices(result_keys, k=random.randint(5, 15))
        s.errors = random.choices(error_keys, k=random.randint(0, 3))
        s_file_hashes = list(set([x[:64] for x in s.results]).union(set([x[:64] for x in s.errors])))
        s.error_count = len(s.errors)
        s.file_count = len(s_file_hashes)
        for f in s.files:
            f.sha256 = random.choice(s_file_hashes)
        ds.submission.save(s.sid, s)
        submissions.append({"sid": s.sid, "file": s.files[0].sha256})
        log.info(f"\t{s.sid}")

    log.info("\nCreating 50 Alerts...")
    for x in range(50):
        submission = random.choice(submissions)
        a = random_model_obj(Alert)
        a.file.sha256 = submission['file']
        a.sid = submission['sid']
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
