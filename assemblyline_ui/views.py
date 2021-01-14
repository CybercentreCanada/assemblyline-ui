import hashlib
import json
import markdown

from authlib.integrations.requests_client import OAuth2Session
from flask import Blueprint, render_template, request, abort, redirect, Markup, current_app

from assemblyline.common.isotime import iso_to_local
from assemblyline.common import forge
from assemblyline_ui.config import STORAGE, ORGANISATION, get_signup_queue, get_reset_queue, get_token_store
from assemblyline_ui.helper.oauth import parse_profile, fetch_avatar
from assemblyline_ui.helper.search import list_all_fields
from assemblyline_ui.helper.views import protected_renderer, custom_render, redirect_helper, angular_safe
from assemblyline.odm.models.user import User

config = forge.get_config()

Classification = forge.get_classification()

views = Blueprint("views", __name__, template_folder="templates")


######################################
# All users pages
@views.route("/account.html")
@protected_renderer(audit=False)
def account(**kwargs):
    return custom_render("account.html", **kwargs)


# noinspection PyBroadException
@views.route("/alerts.html")
@protected_renderer(audit=False, load_settings=True)
def alerts(*_, **kwargs):
    filtering_group_fields = config.core.alerter.filtering_group_fields
    non_filtering_group_fields = config.core.alerter.non_filtering_group_fields
    possible_group_fields = filtering_group_fields + non_filtering_group_fields

    search_filter = angular_safe(request.args.get("filter", "*"))

    search_text = search_filter
    if search_filter == "":
        search_filter = "*"
    elif search_filter == "*":
        search_text = ""

    filter_queries = [angular_safe(x) for x in request.args.getlist("fq") if x != ""]

    tc = angular_safe(request.args.get("tc", "4{DAY}".format(**STORAGE.ds.DATE_FORMAT)))
    tc_array = [
        {"value": "", "name": "None (slow)"},
        {"value": "24{HOUR}".format(**STORAGE.ds.DATE_FORMAT), "name": "24 Hours"},
        {"value": "4{DAY}".format(**STORAGE.ds.DATE_FORMAT), "name": "4 Days"},
        {"value": "7{DAY}".format(**STORAGE.ds.DATE_FORMAT), "name": "1 Week"}
    ]
    tc_start = angular_safe(request.args.get("tc_start", None))
    view_type = angular_safe(request.args.get("view_type", "grouped"))
    group_by = angular_safe(request.args.get("group_by", config.core.alerter.default_group_field))
    if group_by not in possible_group_fields:
        group_by = config.core.alerter.default_group_field

    return custom_render("alerts.html",
                         search_text=search_text,
                         filter=search_filter,
                         tc_start=tc_start,
                         tc=tc,
                         view_type=view_type,
                         filter_queries=json.dumps(filter_queries),
                         group_by=group_by,
                         filtering_group_fields=json.dumps(filtering_group_fields),
                         non_filtering_group_fields=json.dumps(non_filtering_group_fields),
                         tc_array=tc_array,
                         time_separator=angular_safe(STORAGE.ds.DATE_FORMAT["SEPARATOR"]),
                         **kwargs)


@views.route("/alert_detail.html")
@protected_renderer(audit=False, load_settings=True)
def alert_detail(*_, **kwargs):
    user = kwargs['user']

    alert_key = angular_safe(request.args.get("alert_key", None))
    if not alert_key:
        abort(404)

    alert = STORAGE.alert.get(alert_key, as_obj=False)
    if user and alert and Classification.is_accessible(user['classification'], alert['classification']):
        return custom_render("alert_detail.html", alert_key=alert_key, **kwargs)
    else:
        abort(403)


@views.route("/api_doc.html")
@protected_renderer(audit=False)
def api_doc(**kwargs):
    return custom_render("api_doc.html", **kwargs)


@views.route("/classification_help.html")
@protected_renderer(audit=False)
def classification_help(*_, **kwargs):
    return custom_render("classification_help.html", **kwargs)


@views.route("/configuration.html")
@protected_renderer(audit=False, allow_readonly=False)
def configuration(**kwargs):
    return custom_render("configuration.html", **kwargs)


@views.route("/dashboard.html")
@protected_renderer(audit=False, allow_readonly=False)
def dashboard(**kwargs):
    return custom_render("dashboard.html", **kwargs)


@views.route("/")
@protected_renderer(audit=False)
def default(**kwargs):
    return submit(**kwargs)


@views.route("/file_detail.html", methods=["GET"])
@protected_renderer(load_settings=True, audit=False)
def file_detail(**kwargs):
    user = kwargs['user']
    sha256 = angular_safe(request.args.get("sha256", None))

    if not sha256:
        abort(404)

    data = STORAGE.file.get(sha256, as_obj=False)

    if not data:
        abort(404)

    if not Classification.is_accessible(user['classification'], data['classification']):
        abort(403)

    return custom_render("file_detail.html", sha256=sha256, **kwargs)


@views.route("/file_viewer.html")
@protected_renderer(audit=False)
def file_viewer(**kwargs):
    user = kwargs['user']
    sha256 = angular_safe(request.args.get("sha256", None))

    if not sha256:
        abort(404)

    data = STORAGE.file.get(sha256, as_obj=False)

    if not data:
        abort(404)

    if not Classification.is_accessible(user['classification'], data['classification']):
        abort(403)

    return custom_render("file_viewer.html", sha256=sha256, **kwargs)


# Site-Specific heuristics page
@views.route("/heuristics.html")
@protected_renderer(audit=False, allow_readonly=False)
def heuristics(*_, **kwargs):
    return custom_render("heuristics.html", **kwargs)


@views.route("/heuristics_stats.html")
@protected_renderer(audit=False, allow_readonly=False)
def heuristics_stats(*_, **kwargs):
    return custom_render("heuristics_stats.html", **kwargs)


@views.route("/oauth/<provider>/")
def oauth(provider):
    return redirect(redirect_helper(f"/login.html?provider={provider}&{request.query_string.decode()}"))


@views.route("/login.html")
def login():
    ui4_path = request.cookies.get('ui4_path', None)
    if ui4_path is not None:
        resp = redirect(redirect_helper(f"{ui4_path}?{request.query_string.decode()}"))
        resp.delete_cookie("ui4_path")
        return resp

    registration_key = request.args.get('registration_key', None)

    avatar = None
    oauth_token = ''
    oauth_error = ''
    username = ''
    oauth_validation = config.auth.oauth.enabled and 'code' in request.args and 'state' in request.args
    oauth_provider = request.args.get('provider', None)
    up_login = config.auth.internal.enabled or config.auth.ldap.enabled

    next_url = angular_safe(request.args.get('next', request.cookies.get('next_url', "/")))
    if "login.html" in next_url or "logout.html" in next_url:
        next_url = "/"

    if registration_key and config.auth.internal.signup.enabled:
        try:
            signup_queue = get_signup_queue(registration_key)
            members = signup_queue.members()
            signup_queue.delete()
            if members:
                user_info = members[0]
                user = User(user_info)
                username = user.uname

                STORAGE.user.save(username, user)
        except (KeyError, ValueError):
            pass

    if config.auth.oauth.enabled:
        providers = str([name for name, p in config.auth.oauth.providers.items()
                         if p['client_id'] and p['client_secret']])

        if oauth_validation:
            oauth = current_app.extensions.get('authlib.integrations.flask_client')
            provider = oauth.create_client(oauth_provider)

            if provider:
                # noinspection PyBroadException
                try:
                    oauth_provider_config = config.auth.oauth.providers[oauth_provider]
                    if oauth_provider_config.app_provider:
                        # Validate the token that we've received using the secret
                        token = provider.authorize_access_token(client_secret=oauth_provider_config.client_secret)

                        # Initialize the app_provider
                        app_provider = OAuth2Session(
                            oauth_provider_config.app_provider.client_id or oauth_provider_config.client_id,
                            oauth_provider_config.app_provider.client_secret or oauth_provider_config.client_secret,
                            scope=oauth_provider_config.app_provider.scope)
                        app_provider.fetch_token(
                            oauth_provider_config.app_provider.access_token_url,
                            grant_type="client_credentials")

                    else:
                        # Validate the token
                        token = provider.authorize_access_token()
                        app_provider = None

                    user_data = None
                    if oauth_provider_config.jwks_uri:
                        user_data = provider.parse_id_token(token)

                    # Get user data from endpoint
                    if app_provider and oauth_provider_config.app_provider.user_get:
                        url = oauth_provider_config.app_provider.user_get
                        uid = user_data.get('id', None)
                        if not uid and user_data and oauth_provider_config.uid_field:
                            uid = user_data.get(oauth_provider_config.uid_field, None)
                        if uid:
                            url = url.format(id=uid)
                        resp = app_provider.get(url)
                        if resp.ok:
                            user_data = resp.json()
                    elif not user_data:
                        resp = provider.get(oauth_provider_config.user_get)
                        if resp.ok:
                            user_data = resp.json()

                    # Add group data if API is configured for it
                    if oauth_provider_config.user_groups:
                        groups = []
                        if app_provider and oauth_provider_config.app_provider.group_get:
                            url = oauth_provider_config.app_provider.group_get
                            uid = user_data.get('id', None)
                            if not uid and user_data and oauth_provider_config.uid_field:
                                uid = user_data.get(oauth_provider_config.uid_field, None)
                            if uid:
                                url = url.format(id=uid)
                            resp_grp = app_provider.get(url)
                            if resp_grp.ok:
                                groups = resp_grp.json()
                        else:
                            resp_grp = provider.get(oauth_provider_config.user_groups)
                            if resp_grp.ok:
                                groups = resp_grp.json()

                        if oauth_provider_config.user_groups_data_field:
                            groups = groups[oauth_provider_config.user_groups_data_field]

                        if oauth_provider_config.user_groups_name_field:
                            groups = [x[oauth_provider_config.user_groups_name_field] for x in groups]

                        if groups:
                            user_data['groups'] = groups

                    if user_data:
                        data = parse_profile(user_data, oauth_provider_config)
                        has_access = data.pop('access', False)
                        if has_access:
                            oauth_avatar = data.pop('avatar', None)

                            # Find if user already exists
                            users = STORAGE.user.search(f"email:{data['email']}", fl="uname", as_obj=False)['items']
                            if users:
                                cur_user = STORAGE.user.get(users[0]['uname'], as_obj=False) or {}
                                # Do not update username and password from the current user
                                data['uname'] = cur_user.get('uname', data['uname'])
                                data['password'] = cur_user.get('password', data['password'])
                            else:
                                if data['uname'] != data['email']:
                                    # Username was computed using a regular expression, lets make sure we don't
                                    # assign the same username to two users
                                    res = STORAGE.user.search(f"uname:{data['uname']}", rows=0, as_obj=False)
                                    if res['total'] > 0:
                                        cnt = res['total']
                                        new_uname = f"{data['uname']}{cnt}"
                                        while STORAGE.user.get(new_uname) is not None:
                                            cnt += 1
                                            new_uname = f"{data['uname']}{cnt}"
                                        data['uname'] = new_uname
                                cur_user = {}

                            username = data['uname']

                            # Make sure the user exists in AL and is in sync
                            if (not cur_user and oauth_provider_config.auto_create) or \
                                    (cur_user and oauth_provider_config.auto_sync):

                                # Update the current user
                                cur_user.update(data)

                                # Save avatar
                                if oauth_avatar:
                                    avatar = fetch_avatar(oauth_avatar, provider, oauth_provider_config)
                                    if avatar:
                                        STORAGE.user_avatar.save(username, avatar)

                                # Save updated user
                                STORAGE.user.save(username, cur_user)

                            if cur_user:
                                if avatar is None:
                                    avatar = STORAGE.user_avatar.get(username) or "/static/images/user_default.png"
                                oauth_token = hashlib.sha256(str(token).encode("utf-8", errors='replace')).hexdigest()
                                get_token_store(username).add(oauth_token)
                            else:
                                oauth_validation = False
                                avatar = None
                                username = ''
                                oauth_error = "User auto-creation is disabled"
                        else:
                            oauth_validation = False
                            oauth_error = "This user is not allowed access to the system"

                except Exception as _:
                    oauth_validation = False
                    oauth_error = "Invalid oAuth2 token, try again"
    else:
        providers = str([])

    return custom_render("login.html", next=next_url, avatar=avatar, username=username, oauth_error=oauth_error,
                         oauth_token=oauth_token, providers=providers,
                         signup=config.auth.internal.enabled and config.auth.internal.signup.enabled,
                         oauth_validation=str(oauth_validation).lower(), up_login=str(up_login).lower())


@views.route("/logout.html")
@protected_renderer(load_settings=False, audit=False)
def logout(**_):
    return custom_render("logout.html",)


@views.route("/report.html", methods=["GET"])
@protected_renderer(load_settings=True)
def report(**kwargs):
    sid = angular_safe(request.args.get("sid", None))
    return custom_render("report.html", sid=sid, **kwargs)


# noinspection PyBroadException
@views.route("/reset.html")
def reset():
    if not config.auth.internal.signup.enabled:
        return redirect(redirect_helper("/"))

    reset_id = request.args.get('reset_id', "")
    if reset_id and get_reset_queue(reset_id).length() == 0:
        reset_id = ""
    return custom_render("reset.html", reset_id=reset_id)


@views.route("/search.html")
@protected_renderer(load_settings=True, audit=False)
def search(**kwargs):
    query = angular_safe(request.args.get('query', None))
    search_scope = angular_safe(request.args.get('search_scope', None))
    if search_scope == 'all':
        search_scope = None
    use_archive = angular_safe(request.args.get('use_archive', "unset")).lower()
    if use_archive not in ['false', 'true']:
        use_archive = None

    return custom_render("search.html", query=query, search_scope=search_scope, use_archive=use_archive, **kwargs)


@views.route("/search_help.html")
@protected_renderer(audit=False)
def search_help(**kwargs):
    field_list = {k: sorted([(x, y) for x, y in v.items()])
                  for k, v in list_all_fields().items()}
    lookup = {
        "text_ws": "whitespace separated text",
        "text_ws_dsplit": "dot and whitespace separated text",
        "text_general": "tokenized text",
        "text_fuzzy": "separated fuzzy patterns",
    }
    return custom_render("search_help.html", field_list=field_list, lookup=lookup, **kwargs)


@views.route("/services.html")
@protected_renderer(audit=False, allow_readonly=False)
def services(**kwargs):
    return custom_render("services.html", **kwargs)


@views.route("/settings.html")
@protected_renderer(audit=False)
def settings(**kwargs):
    forced = 'forced' in request.args
    if forced:
        forced = 'true'
    else:
        forced = 'false'
    return custom_render("settings.html", forced=forced, **kwargs)


@views.route("/signature_detail.html", methods=["GET"])
@protected_renderer(load_settings=True, audit=False, allow_readonly=False)
def signature_detail(**kwargs):
    user = kwargs['user']
    sid = angular_safe(request.args.get("sid", None))

    if not sid:
        abort(404)

    data = STORAGE.signature.get(sid, as_obj=False)

    if not data:
        abort(404)

    if not Classification.is_accessible(user['classification'],
                                        data.get('classification', Classification.UNRESTRICTED)):
        abort(403)

    return custom_render("signature_detail.html",
                         sid=sid,
                         organisation=ORGANISATION,
                         **kwargs)


@views.route("/signatures.html")
@protected_renderer(audit=False, allow_readonly=False)
def signatures(**kwargs):
    return custom_render("signatures.html", org=ORGANISATION, **kwargs)


@views.route("/source_management.html")
@protected_renderer(audit=False, allow_readonly=False, require_type=['admin', 'signature_manager'])
def signature_management(**kwargs):
    return custom_render("source_management.html", **kwargs)


@views.route("/signature_statistics.html")
@protected_renderer(audit=False, allow_readonly=False)
def signature_statistics(*_, **kwargs):
    return custom_render("signature_statistics.html", **kwargs)


@views.route("/submission_detail.html", methods=["GET"])
@protected_renderer(load_settings=True)
def submission_detail(**kwargs):
    sid = angular_safe(request.args.get("sid", None))
    new = "new" in request.args
    if new:
        new = 'true'
    else:
        new = 'false'
    return custom_render("submission_detail.html", sid=sid, new=new, **kwargs)


@views.route("/submissions.html")
@protected_renderer(audit=False, load_settings=True)
def submissions(**kwargs):
    user = kwargs['user']

    group = angular_safe(request.args.get('group', None))
    uname = None

    if not group:
        uname = angular_safe(request.args.get('user', user['uname']))

    return custom_render("submissions.html", uname=uname, group=group, **kwargs)


@views.route("/submit.html")
@protected_renderer(audit=False)
def submit(**kwargs):
    show_tos = config.ui.tos is not None
    show_url = config.ui.allow_url_submissions
    return custom_render("submit.html", show_tos=show_tos, show_url=show_url, **kwargs)


@views.route("/terms.html")
@protected_renderer(audit=False)
def tos(**kwargs):
    if config.ui.tos is not None:
        kwargs['menu'] = None
        agreed_date = kwargs['user'].get('agrees_with_tos', None)
        if agreed_date:
            agreed_date = iso_to_local(agreed_date)[:19]
        tos_raw = Markup(markdown.markdown(config.ui.tos))
        return custom_render("terms.html", tos=tos_raw, agreed_date=agreed_date, **kwargs)
    else:
        return redirect(redirect_helper("/"))


@views.route("/unsupported.html")
def unsupported():
    return render_template("unsupported.html", user_agent=request.environ["HTTP_USER_AGENT"])


@views.route("/workflows.html")
@protected_renderer(audit=False, allow_readonly=False)
def workflows(**kwargs):
    return custom_render("workflows.html", **kwargs)


############################################
# Admin Protected pages
@views.route("/admin/errors.html")
@protected_renderer(require_type=['admin'], audit=False)
def admin_errors(**kwargs):
    query = angular_safe(request.args.get('filter', ""))
    return custom_render("admin_errors.html", filter=query, **kwargs)


@views.route("/admin/services.html")
@protected_renderer(require_type=['admin'], audit=False, allow_readonly=False)
def admin_services(**kwargs):
    return custom_render("admin_service_configs.html", **kwargs)


@views.route("/admin/site_map.html")
@protected_renderer(require_type=['admin'], audit=False)
def admin_site_map(**kwargs):
    return custom_render("admin_site_map.html", **kwargs)


@views.route("/admin/users.html")
@protected_renderer(require_type=['admin'], audit=False)
def admin_user(**kwargs):
    return custom_render("admin_users.html", **kwargs)
