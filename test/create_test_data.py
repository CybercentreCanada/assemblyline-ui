import pprint

from assemblyline.common.security import get_password_hash
from assemblyline.common import forge
from assemblyline.odm.models.service import Service
from assemblyline.odm.models.user import User

print("Loading datastore...")
ds = forge.get_datastore()

print("\nCreating user object...")
user_data = User({"name": "Admin user", "password": get_password_hash("admin"), "uname": "admin", "is_admin": True})
ds.user.save('admin', user_data)
pprint.pprint(user_data.as_primitives())
user_data = User({"name": "user", "password": get_password_hash("user"), "uname": "user"})
ds.user.save('user', user_data)
pprint.pprint(user_data.as_primitives())

print("\nCreating services...")
service_data = Service({"class_name": "PEFile", "classpath": "assemblyline_services.pefile.PEFile", "name": "PEFile", "realm": "bitbucket", "repo": "alsvc_pefile", "enabled": True})
ds.service.save('PEFile', service_data)
print('\tPEFile')
service_data = Service({"class_name": "Extract", "classpath": "assemblyline_services.extract.Extract", "name": "Extract", "realm": "bitbucket", "repo": "alsvc_extract", "enabled": True, "category": "Extraction"})
ds.service.save('Extract', service_data)
print('\tExtract')

print("\nDone.")
