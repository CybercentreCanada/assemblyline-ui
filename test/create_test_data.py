import random

from assemblyline.common.security import get_password_hash
from assemblyline.common import forge
from assemblyline.odm.models.emptyresult import EmptyResult
from assemblyline.odm.models.error import Error
from assemblyline.odm.models.file import File
from assemblyline.odm.models.result import Result
from assemblyline.odm.models.service import Service
from assemblyline.odm.models.submission import Submission
from assemblyline.odm.models.user import User
from assemblyline.odm.randomizer import random_model_obj, SERVICES

print("Loading datastore...")
ds = forge.get_datastore()

print("\nCreating user object...")
user_data = User({"name": "Admin user", "password": get_password_hash("admin"), "uname": "admin", "is_admin": True})
ds.user.save('admin', user_data)
print(f"\tU:{user_data.uname}   P:{user_data.uname}")
user_data = User({"name": "user", "password": get_password_hash("user"), "uname": "user"})
ds.user.save('user', user_data)
print(f"\tU:{user_data.uname}    P:{user_data.uname}")

print("\nCreating services...")
for svc in SERVICES:
    service_data = Service({"class_name": svc, "classpath": f"assemblyline_services.{svc.lower()}.{svc}", "name": svc,
                            "realm": "bitbucket", "repo": f"alsvc_{svc.lower()}", "enabled": True})
    ds.service.save('PEFile', service_data)
    print(f'\t{svc}')

print("\nCreating 20 Files...")
file_hashes = []
for x in range(20):
    f = random_model_obj(File)
    file_hashes.append(f.sha256)
    ds.file.save(f.sha256, f)
    print(f"\t{f.sha256}")

print("\nCreating 6 Results per file...")
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

        key = r.build_key()
        result_keys.append(key)
        ds.result.save(key, r)
        print(f"\t{key}")

print("\nCreating 4 EmptyResults per file...")
for fh in file_hashes:
    other_files = list(set(file_hashes) - {fh})

    for x in range(4):
        # Get a random result key
        r = random_model_obj(Result)
        r.sha256 = fh
        key = f"{r.build_key()}.e"
        result_keys.append(key)

        # Save an empty result using that key
        ds.emptyresult.save(key, random_model_obj(EmptyResult))
        print(f"\t{key}")

print("\nCreating 2 Errors per file...")
error_keys = []
for fh in file_hashes:
    for x in range(2):
        e = random_model_obj(Error)
        e.sha256 = fh
        key = e.build_key()
        error_keys.append(key)
        ds.error.save(key, e)
        print(f"\t{key}")

print("\nCreating 10 Submissions...")
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
    print(f"\t{s.sid}")


print("\nDone.")
