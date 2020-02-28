import base64
import hashlib
import requests

from assemblyline_ui.config import config


def parse_profile(profile):
    email_adr = profile.get('email', profile.get('upn', None))

    if config.auth.oauth.gravatar_enabled:
        email_hash = hashlib.md5(email_adr.encode('utf-8')).hexdigest()
        alternate = f"https://www.gravatar.com/avatar/{email_hash}?s=256&d=404&r=pg"
    else:
        alternate = None

    return dict(
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
