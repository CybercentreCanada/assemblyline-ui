import base64
import hashlib
import re
import requests

from assemblyline.common import forge
from assemblyline_ui.config import config

cl_engine = forge.get_classification()


def parse_profile(profile, auto_prop_list=None):
    if not auto_prop_list:
        auto_prop_list = []

    email_adr = profile.get('email', profile.get('upn', None))

    if config.auth.oauth.gravatar_enabled:
        email_hash = hashlib.md5(email_adr.encode('utf-8')).hexdigest()
        alternate = f"https://www.gravatar.com/avatar/{email_hash}?s=256&d=404&r=pg"
    else:
        alternate = None

    access = True
    roles = ['user']
    classification = cl_engine.UNRESTRICTED
    for auto_prop in auto_prop_list:
        if auto_prop.type == "access":
            if auto_prop.value == "True":
                access = re.match(auto_prop.pattern, profile.get(auto_prop.field, "")) is not None
            else:
                access = re.match(auto_prop.pattern, profile.get(auto_prop.field, "")) is None
        elif auto_prop.type == "role":
            if re.match(auto_prop.pattern, profile.get(auto_prop.field, "")):
                roles.append(auto_prop.value)
        elif auto_prop.type == "classification":
            if re.match(auto_prop.pattern, profile.get(auto_prop.field, "")):
                classification = cl_engine.max_classification(classification, auto_prop.value)

    return dict(
        access=access,
        type=roles,
        classification=classification,
        uname=profile.get('uname', email_adr),
        name=profile.get('name', None),
        email=email_adr,
        password="__NO_PASSWORD__",
        avatar=profile.get('picture', alternate)
    )


def fetch_avatar(url):
    if url.startswith('https://') or url.startswith('http://'):
        resp = requests.get(url)
        if resp.ok and resp.headers.get("content-type") is not None:
            b64_img = base64.b64encode(resp.content).decode()
            avatar = f'data:{resp.headers.get("content-type")};base64,{b64_img}'
            return avatar
