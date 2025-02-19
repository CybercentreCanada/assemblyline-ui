import base64
import hashlib
import re
import requests

from authlib.integrations.flask_client import FlaskOAuth2App
from assemblyline.odm.models.config import OAuthProvider
from assemblyline.odm.models.user import load_roles, USER_TYPE_DEP
from assemblyline.common.random_user import random_user
from assemblyline_ui.config import config, CLASSIFICATION as cl_engine

VALID_CHARS = [str(x) for x in range(10)] + [chr(x + 65) for x in range(26)] + [chr(x + 97) for x in range(26)] + ["-"]


def reorder_name(name):
    if name is None:
        return name

    return " ".join(name.split(", ", 1)[::-1])

def get_profile_identifiers(profile: dict, provider: OAuthProvider):
    # Find email address and normalize it for further processing
    email_adr = None
    for email_key in provider.email_fields:
        email_adr = profile.get(email_key, None)
        if email_adr:
            break

    if isinstance(email_adr, list):
        email_adr = email_adr[0]

    if email_adr:
        email_adr = email_adr.lower()
        if "@" not in email_adr:
            email_adr = None

    # Find identity ID
    identity_id = profile.get(provider.identity_id_field, None)

    return dict(
        email=email_adr,
        identity_id=identity_id
    )

def parse_profile(profile: dict, provider: OAuthProvider):
    profile_identifiers = get_profile_identifiers(profile, provider)
    email_adr = profile_identifiers['email']

    # Find the name of the user
    name = reorder_name(profile.get('name', profile.get('displayName', None)))

    # Generate a username
    if provider.uid_randomize:
        # Use randomizer
        uname = random_user(digits=provider.uid_randomize_digits, delimiter=provider.uid_randomize_delimiter)
    else:
        # Generate it from email address
        uname = profile.get(provider.username_field, email_adr)

        # 1. Use provided regex matcher
        if uname is not None and uname == email_adr and provider.uid_regex:
            match = re.match(provider.uid_regex, uname)
            if match:
                if provider.uid_format:
                    uname = provider.uid_format.format(*[x or "" for x in match.groups()]).lower()
                else:
                    uname = ''.join([x for x in match.groups() if x is not None]).lower()

        # 2. Parse name and domain form email if regex failed or missing
        if uname is not None and uname == email_adr:
            e_name, e_dom = uname.split("@", 1)
            uname = f"{e_name}-{e_dom.split('.')[0]}"

        # 3. Use name as username if there are no username found yet
        if uname is None and name is not None:
            uname = name.replace(" ", "-")

        # Cleanup username
        if uname:
            uname = "".join([c for c in uname if c in VALID_CHARS])

    # Get avatar from gravatar
    if config.auth.oauth.gravatar_enabled and email_adr:
        email_hash = hashlib.md5(email_adr.encode('utf-8')).hexdigest()
        alternate = f"https://www.gravatar.com/avatar/{email_hash}?s=256&d=404&r=pg"
    else:
        alternate = None

    # Compute access, user_type, roles and classification using auto_properties
    access = True
    access_set = False
    user_type = []
    roles = []
    groups = []
    remove_roles = set()
    quotas = {}
    classification = cl_engine.UNRESTRICTED
    if provider.auto_properties:
        for auto_prop in provider.auto_properties:
            if auto_prop.type == "access" and not access_set:
                # Set default access value for access pattern
                access = auto_prop.value[0].lower() != "true"
                access_set = True

            # Get values for field
            field_data = profile.get(auto_prop.field, None)
            if not isinstance(field_data, list):
                field_data = [field_data]

            # Analyse field values
            for value in field_data:
                # If there is no value, no need to do any tests
                if value is None:
                    continue

                # Check access
                if auto_prop.type == "access":
                    if re.match(auto_prop.pattern, value) is not None:
                        access = auto_prop.value[0].lower() == "true"
                        break

                # Append user type from matching patterns
                elif auto_prop.type == "type":
                    if re.match(auto_prop.pattern, value):
                        user_type.extend(auto_prop.value)
                        break

                # Append roles from matching patterns
                elif auto_prop.type == "role":
                    if re.match(auto_prop.pattern, value):
                        for ap_val in auto_prop.value:
                            # Did we just put an account type in the roles field?
                            if ap_val in USER_TYPE_DEP:
                                # Support of legacy configurations
                                user_type.append(ap_val)
                                roles = list(set(roles).union(USER_TYPE_DEP[ap_val]))
                            else:
                                roles.append(ap_val)
                        break

                # Remove roles from matching patterns
                elif auto_prop.type == "remove_role":
                    if re.match(auto_prop.pattern, value):
                        for ap_val in auto_prop.value:
                            remove_roles.add(ap_val)
                        break

                # Compute classification from matching patterns
                elif auto_prop.type == "classification":
                    if re.match(auto_prop.pattern, value):
                        for ap_val in auto_prop.value:
                            classification = cl_engine.build_user_classification(classification, ap_val)
                        break

                # Append groups from matching patterns
                elif auto_prop.type == "group":
                    group_match = re.match(auto_prop.pattern, value)
                    if group_match:
                        for group_value in auto_prop.value:
                            for index, gm_value in enumerate(group_match.groups()):
                                group_value = group_value.replace(f"${index+1}", gm_value)
                            groups.append(group_value)

                # Append multiple groups from a single matching pattern
                elif auto_prop.type == "multi_group":
                    all_matches = re.findall(auto_prop.pattern, value)
                    for group_match in all_matches:
                        for group_value in auto_prop.value:
                            if not isinstance(group_match, tuple):
                                group_match = (group_match)
                            for index, gm_value in enumerate(group_match):
                                group_value = group_value.replace(f"${index+1}", gm_value)
                            if group_value not in groups:
                                groups.append(group_value)

                # Set API and Submission quotas
                elif auto_prop.type in ['api_quota', 'api_daily_quota', 'submission_quota',
                                        'submission_async_quota', 'submission_daily_quota']:
                    if re.match(auto_prop.pattern, value):
                        quotas[auto_prop.type] = int(auto_prop.value[0])

    # if not user type was assigned
    if not user_type:
        # if also no roles were assigned
        if not roles:
            # Set the default user type
            user_type = ['user']
        else:
            # Because roles were assigned set user type to custom
            user_type = ['custom']

    # Properly load roles based of user type
    roles = load_roles(user_type, roles)

    # Remove all roles marked for removal
    roles = [role for role in roles if role not in remove_roles]

    return dict(
        access=access,
        type=user_type,
        roles=roles,
        groups=groups,
        classification=classification,
        uname=uname,
        name=name,
        email=email_adr,
        identity_id=profile_identifiers['identity_id'],
        password="__NO_PASSWORD__",
        avatar=profile.get('picture', alternate),
        **quotas
    )


def fetch_avatar(url: str, provider: FlaskOAuth2App, provider_config:OAuthProvider):
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
