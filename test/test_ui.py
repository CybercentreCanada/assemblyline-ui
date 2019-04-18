import pytest

from assemblyline.common.security import get_password_hash
from assemblyline.common.yara import YaraImporter
from assemblyline.odm.models.heuristic import Heuristic
from assemblyline.odm.models.service import Service
from assemblyline.odm.models.user import User
from assemblyline.odm.models.user_settings import UserSettings
from assemblyline.odm.randomizer import SERVICES, random_model_obj, get_random_phrase


class SetupException(Exception):
    pass


class CrashLogger(object):
    def info(self, _):
        pass

    def warn(self, msg):
        raise SetupException(msg)

    def error(self, msg):
        raise SetupException(msg)


def test_create_test_data():
    from assemblyline.common import forge
    ds = forge.get_datastore()

    user_total  = ds.user.search("id:*", rows=0)['total']
    if user_total == 0:
        user_data = User({
            "agrees_with_tos": "NOW",
            "classification": "RESTRICTED",
            "name": "Admin user",
            "password": get_password_hash("admin"),
            "uname": "admin",
            "is_admin": True})
        ds.user.save('admin', user_data)
        ds.user_settings.save('admin', UserSettings())
        user_data = User({"name": "user", "password": get_password_hash("user"), "uname": "user"})
        ds.user.save('user', user_data)
        ds.user_settings.save('user', UserSettings())
        ds.user.commit()
        user_total = ds.user.search("id:*", rows=0)['total']
    assert user_total == 2

    service_total = ds.service_delta.search("id:*", rows=0)['total']
    if service_total == 0:
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
        ds.service_delta.commit()
        ds.service.commit()
        service_total = ds.service_delta.search("id:*", rows=0)['total']
    assert service_total == 14

    signature_total = ds.signature.search("id:*", rows=0)['total']
    if signature_total == 0:
        yp = YaraImporter(logger=CrashLogger())
        parsed = yp.parse_file('al_yara_signatures.yar')
        yp.import_now([p['rule'] for p in parsed])
        ds.signature.commit()
        signature_total = ds.signature.search("id:*", rows=0)['total']
    assert signature_total == 19

    heur_total = ds.heuristic.search("id:*", rows=0)['total']
    if heur_total == 0:
        for _ in range(40):
            h = random_model_obj(Heuristic)
            h.name = get_random_phrase()
            ds.heuristic.save(h.heur_id, h)
        ds.heuristic.commit()
        heur_total = ds.heuristic.search("id:*", rows=0)['total']
    assert heur_total > 0
