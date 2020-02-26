import base64
import requests


def parse_profile(profile):
    user = dict(
        uname=profile.get('unique_name', profile.get('email', None)),
        name=profile.get('name', None),
        email=profile.get('email', profile.get('upn', None)),
        password="__OAUTH2__"
    )

    picture = profile.get('picture', None)
    if picture:
        if picture.startswith('https://'):
            resp = requests.get(picture)
            if resp.ok and resp.headers.get("content-type") is not None:
                b64_img = base64.b64encode(resp.content).decode()
                avatar = f'data:{resp.headers.get("content-type")};base64,{b64_img}'
                user['avatar'] = avatar

    return user
