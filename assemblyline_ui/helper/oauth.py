import base64
import hashlib
import re
import requests

from assemblyline.common import forge
from assemblyline_ui.config import config

cl_engine = forge.get_classification()


def parse_profile(profile, provider):
    # Find email address
    email_adr = profile.get('email', profile.get('upn', None))

    # Find username or compute it from email
    uname = profile.get('uname', email_adr)
    if uname == email_adr and provider.uid_regex:
        match = re.match(provider.uid_regex, uname)
        if match:
            if provider.uid_format:
                uname = provider.uid_format.format(*[x or "" for x in match.groups()]).lower()
            else:
                uname = ''.join([x for x in match.groups() if x is not None]).lower()

    # Get avatar from gravatar
    if config.auth.oauth.gravatar_enabled:
        email_hash = hashlib.md5(email_adr.encode('utf-8')).hexdigest()
        alternate = f"https://www.gravatar.com/avatar/{email_hash}?s=256&d=404&r=pg"
    else:
        alternate = None

    # Compute access, roles and classification using auto_properties
    access = True
    roles = ['user']
    classification = cl_engine.UNRESTRICTED
    if provider.auto_properties:
        for auto_prop in provider.auto_properties:
            if auto_prop.type == "access":
                # Check access
                if auto_prop.value == "True":
                    # If its a positive access pattern
                    access = re.match(auto_prop.pattern, profile.get(auto_prop.field, "")) is not None
                else:
                    # If its a negative access pattern
                    access = re.match(auto_prop.pattern, profile.get(auto_prop.field, "")) is None
            elif auto_prop.type == "role":
                # Append roles from matching patterns
                if re.match(auto_prop.pattern, profile.get(auto_prop.field, "")):
                    roles.append(auto_prop.value)
            elif auto_prop.type == "classification":
                # Compute classification from matching patterns
                if re.match(auto_prop.pattern, profile.get(auto_prop.field, "")):
                    classification = cl_engine.max_classification(classification, auto_prop.value)

    return dict(
        access=access,
        type=roles,
        classification=classification,
        uname=uname,
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
