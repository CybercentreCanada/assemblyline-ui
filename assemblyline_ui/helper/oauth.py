import base64
import hashlib
import re
from typing import Optional
from urllib.parse import urlsplit

import requests
from assemblyline.common.random_user import random_user
from assemblyline.odm.models.config import OAuthProvider
from assemblyline.odm.models.user import load_roles
from assemblyline_ui.config import CLASSIFICATION as cl_engine
from assemblyline_ui.config import LOGGER, config
from assemblyline_ui.security.utils import process_autoproperties
from authlib.integrations.flask_client import FlaskOAuth2App

VALID_CHARS = [str(x) for x in range(10)] + [chr(x + 65) for x in range(26)] + [chr(x + 97) for x in range(26)] + ["-"]
MAX_AVATAR_SIZE = 5 * 1024 * 1024


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

    # Generate user details based off auto-properties configuration
    access, user_type, roles, organization, groups, remove_roles, quotas, classification, default_metadata = process_autoproperties(provider.auto_properties, profile, cl_engine.UNRESTRICTED)

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
        organization=organization,
        default_metadata=default_metadata,
        **quotas
    )


def _host_matches(hostname: str, allowed: str) -> bool:
    allowed = allowed.lower().rstrip('.')
    if allowed.startswith('*.'):
        return hostname.endswith(allowed[1:]) or hostname == allowed[2:]
    return hostname == allowed


def _encode_avatar(url: str, resp, content: Optional[bytes] = None) -> Optional[str]:
    if not resp.ok:
        LOGGER.warning(f"Avatar download failed with status {resp.status_code}: {url}")
        return None

    content_type = resp.headers.get("content-type", "")
    if not content_type.startswith("image/"):
        LOGGER.warning(f"Avatar rejected, content-type '{content_type}' is not an image: {url}")
        return None

    if content is None:
        content = resp.content
    if len(content) > MAX_AVATAR_SIZE:
        LOGGER.warning(f"Avatar rejected, response larger than {MAX_AVATAR_SIZE} bytes: {url}")
        return None

    b64_img = base64.b64encode(content).decode()
    return f'data:{content_type};base64,{b64_img}'


def fetch_avatar(url: str, provider: FlaskOAuth2App, provider_config: OAuthProvider):
    parts = urlsplit(url)
    if parts.scheme != 'https':
        LOGGER.warning(f"Avatar rejected, only https:// URLs are allowed: {url}")
        return None

    hostname = (parts.hostname or "").lower().rstrip('.')
    if not hostname:
        LOGGER.warning(f"Avatar rejected, URL has no valid hostname: {url}")
        return None

    api_base_host = (urlsplit(provider_config.api_base_url or "").hostname or "").lower().rstrip('.')

    # Avatars hosted on the provider's API are fetched with the user's OAuth token
    if hostname == api_base_host and url.startswith(provider_config.api_base_url):
        resp = provider.get(url[len(provider_config.api_base_url):])
        return _encode_avatar(url, resp)

    # Any other URL must target an explicitly allowed host
    allowed_hosts = list(provider_config.avatar_allowed_hosts)
    if config.auth.oauth.gravatar_enabled:
        allowed_hosts.append("www.gravatar.com")

    if not any(_host_matches(hostname, allowed) for allowed in allowed_hosts):
        LOGGER.warning(f"Avatar rejected, host '{hostname}' is not in avatar_allowed_hosts: {url}")
        return None

    with requests.get(url, allow_redirects=False, timeout=5, stream=True) as resp:
        content = resp.raw.read(MAX_AVATAR_SIZE + 1, decode_content=True)
        return _encode_avatar(url, resp, content)
