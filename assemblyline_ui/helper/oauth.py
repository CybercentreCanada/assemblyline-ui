import base64
import requests


def parse_profile(profile):
    email_adr = profile.get('email', profile.get('upn', None))
    user = dict(
        uname=profile.get('uname', email_adr),
        name=profile.get('name', None),
        email=email_adr,
        password="__NO_PASSWORD__"
    )

    picture = profile.get('picture', None)
    if picture:
        if picture.startswith('https://') or picture.startswith('http://'):
            resp = requests.get(picture)
            if resp.ok and resp.headers.get("content-type") is not None:
                b64_img = base64.b64encode(resp.content).decode()
                avatar = f'data:{resp.headers.get("content-type")};base64,{b64_img}'
                user['avatar'] = avatar

    return user
