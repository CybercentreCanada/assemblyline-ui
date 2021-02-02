import base64
import hashlib
import re
import requests

from assemblyline.common import forge
from assemblyline.common.random_user import random_user
from assemblyline_ui.config import config

cl_engine = forge.get_classification()
VALID_CHARS = [str(x) for x in range(10)] + [chr(x + 65) for x in range(26)] + \
              [chr(x + 97) for x in range(26)] + ["_", "-", ".", "@"]


def reorder_name(name):
    if name is None:
        return name

    return " ".join(name.split(", ", 1)[::-1])


def parse_profile(profile, provider):
    # Find email address and normalize it for further processing
    email_adr = profile.get('email', profile.get('emails', profile.get('preferred_username', profile.get('upn', None))))

    if isinstance(email_adr, list):
        email_adr = email_adr[0]

    if email_adr:
        email_adr = email_adr.lower()

    if "@" not in email_adr:
        email_adr = None

    # Find the name of the user
    name = reorder_name(profile.get('name', profile.get('displayName', None)))

    # Find username or compute it from email
    if provider.uid_randomize:
        uname = random_user(digits=provider.uid_randomize_digits, delimiter=provider.uid_randomize_delimiter)
    else:
        uname = profile.get('uname', email_adr)
        if uname is not None and uname == email_adr and provider.uid_regex:
            match = re.match(provider.uid_regex, uname)
            if match:
                if provider.uid_format:
                    uname = provider.uid_format.format(*[x or "" for x in match.groups()]).lower()
                else:
                    uname = ''.join([x for x in match.groups() if x is not None]).lower()

        # Use name as username if there are no username
        if uname is None:
            uname = name

        # Cleanup username
        if uname:
            uname = uname.replace(" ", "-")
            uname = "".join([c for c in uname if c in VALID_CHARS])

    # Get avatar from gravatar
    if config.auth.oauth.gravatar_enabled and email_adr:
        email_hash = hashlib.md5(email_adr.encode('utf-8')).hexdigest()
        alternate = f"https://www.gravatar.com/avatar/{email_hash}?s=256&d=404&r=pg"
    else:
        alternate = None

    # Compute access, roles and classification using auto_properties
    first_access = True
    access = True
    roles = ['user']
    classification = cl_engine.UNRESTRICTED
    if provider.auto_properties:
        for auto_prop in provider.auto_properties:
            field_data = profile.get(auto_prop.field, "")
            if not isinstance(field_data, list):
                field_data = [field_data]
            for value in field_data:
                if auto_prop.type == "access":
                    # Check access
                    if auto_prop.value == "True":
                        # If its a positive access pattern
                        if first_access:
                            access = False
                            first_access = False
                        if re.match(auto_prop.pattern, value) is not None:
                            access = True
                            break
                    else:
                        # If its a negative access pattern
                        if first_access:
                            access = True
                            first_access = False
                        if re.match(auto_prop.pattern, value) is not None:
                            access = False
                            break
                elif auto_prop.type == "role":
                    # Append roles from matching patterns
                    if re.match(auto_prop.pattern, value):
                        roles.append(auto_prop.value)
                        break
                elif auto_prop.type == "classification":
                    # Compute classification from matching patterns
                    if re.match(auto_prop.pattern, value):
                        classification = cl_engine.build_user_classification(classification, auto_prop.value)
                        break

    return dict(
        access=access,
        type=roles,
        classification=classification,
        uname=uname,
        name=name,
        email=email_adr,
        password="__NO_PASSWORD__",
        avatar=profile.get('picture', alternate)
    )


def fetch_avatar(url, provider, provider_config):
    if url.startswith(provider_config.api_base_url):
        resp = provider.get(url[len(provider_config.api_base_url):])
        if resp.ok and resp.headers.get("content-type") is not None:
            b64_img = base64.b64encode(resp.content).decode()
            avatar = f'data:{resp.headers.get("content-type")};base64,{b64_img}'
            return avatar

    elif url.startswith('https://') or url.startswith('http://'):
        resp = requests.get(url)
        if resp.ok and resp.headers.get("content-type") is not None:
            b64_img = base64.b64encode(resp.content).decode()
            avatar = f'data:{resp.headers.get("content-type")};base64,{b64_img}'
            return avatar
