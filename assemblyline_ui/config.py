import logging
import os
import requests

from assemblyline.common import forge
from assemblyline.common import log as al_log
from assemblyline.common.archiving import ArchiveManager
from assemblyline.common.identify import Identify
from assemblyline.common.logformat import AL_LOG_FORMAT
from assemblyline.common.version import BUILD_MINOR, FRAMEWORK_VERSION, SYSTEM_VERSION
from assemblyline.datastore.helper import AssemblylineDatastore, MetadataValidator
from assemblyline.filestore import FileStore
from assemblyline.odm.models.config import (
    METADATA_FIELDTYPE_MAP,
    OAuthProvider,
    OPEN_ID_CONFIGURATION_TO_OAUTH_PROVIDER_MAP,
)
from assemblyline.remote.datatypes import get_client
from assemblyline.remote.datatypes.cache import Cache
from assemblyline.remote.datatypes.daily_quota_tracker import DailyQuotaTracker
from assemblyline.remote.datatypes.hash import ExpiringHash, Hash
from assemblyline.remote.datatypes.queues.comms import CommsQueue
from assemblyline.remote.datatypes.queues.named import NamedQueue
from assemblyline.remote.datatypes.set import ExpiringSet
from assemblyline.remote.datatypes.user_quota_tracker import UserQuotaTracker
from assemblyline_ui.helper.ai import get_ai_agent
from assemblyline_ui.helper.ai.base import AIAgentPool
from assemblyline_ui.helper.discover import get_apps_list


def load_openid_configuration(old_config: OAuthProvider, url: str) -> OAuthProvider:
    try:
        with requests.request("GET", url) as resp:
            config_data = resp.json()
            # add associated values using open id configuration ONLY if value not configured in config
            for key_open_id, key_al_config in OPEN_ID_CONFIGURATION_TO_OAUTH_PROVIDER_MAP.items():
                if key_open_id in config_data and not old_config[key_al_config]:
                    old_config[key_al_config] = config_data[key_open_id]

    finally:
        return old_config


config = forge.get_config()

#################################################################
# Configuration

CLASSIFICATION = forge.get_classification()

ALLOW_ZIP_DOWNLOADS = config.ui.allow_zip_downloads
ALLOW_RAW_DOWNLOADS = config.ui.allow_raw_downloads
APP_ID = "https://%s" % config.ui.fqdn
APP_NAME = "Assemblyline"
AUDIT = config.ui.audit
AUDIT_LOGIN = config.ui.audit_login

SECRET_KEY = config.ui.secret_key
SESSION_DURATION = config.ui.session_duration
DEBUG = config.ui.debug
DOWNLOAD_ENCODING = config.ui.download_encoding
DEFAULT_ZIP_PASSWORD = config.ui.default_zip_password
APIKEY_MAX_DTL = config.auth.apikey_max_dtl
MAX_CLASSIFICATION = CLASSIFICATION.UNRESTRICTED
ORGANISATION = config.system.organisation
SYSTEM_TYPE = config.system.type
VERSION = os.environ.get('ASSEMBLYLINE_VERSION', f"{FRAMEWORK_VERSION}.{SYSTEM_VERSION}.{BUILD_MINOR}.dev0")

BUNDLING_DIR = "/var/lib/assemblyline/bundling"

TEMP_DIR = "/var/lib/assemblyline/flowjs/"
TEMP_SUBMIT_DIR = "/var/lib/assemblyline/submit/"

redis_persistent = get_client(config.core.redis.persistent.host, config.core.redis.persistent.port, False)
redis = get_client(config.core.redis.nonpersistent.host, config.core.redis.nonpersistent.port, False)

# Metadata dynamic suggestions
METADATA_SUGGESTIONS = Hash("meta_suggestions", host=redis_persistent)

# Metadata validation for the frontend
UI_METADATA_VALIDATION = {'submit': {}, 'archive': {}}
meta_config = config.submission.metadata.as_primitives()
for section in ['submit', 'archive']:
    for m_name, m_cfg in meta_config[section].items():
        field_cls = METADATA_FIELDTYPE_MAP[m_cfg['validator_type']](**(m_cfg['validator_params'] or {}))
        if m_cfg['validator_type'] != "uri" and hasattr(field_cls, 'validation_regex'):
            # Extract regex validation for UI (except for URI, we'll re-use the existing pattern on the frontend)
            m_cfg['validator_params']['validation_regex'] = field_cls.validation_regex.pattern
        suggestion_key = m_cfg.get('suggestion_key', None)
        if suggestion_key:
            new_suggestions = METADATA_SUGGESTIONS.get(suggestion_key)
            if new_suggestions:
                m_cfg['suggestions'] = m_cfg.get('suggestions', []) + new_suggestions

        UI_METADATA_VALIDATION[section][m_name] = m_cfg

# TRACKERS
QUOTA_TRACKER = UserQuotaTracker('quota', timeout=60 * 2,  # 2 Minutes timeout
                                 redis=redis_persistent)
ASYNC_SUBMISSION_TRACKER = UserQuotaTracker('async_submissions', timeout=24 * 60 * 60,  # 1 day timeout
                                            redis=redis_persistent)
SUBMISSION_TRACKER = UserQuotaTracker('submissions', timeout=60 * 60,  # 60 minutes timeout
                                      redis=redis_persistent)
DAILY_QUOTA_TRACKER = DailyQuotaTracker(redis=redis_persistent)

# UI queues
FLASK_SESSIONS = ExpiringHash("flask_sessions", ttl=SESSION_DURATION, host=redis)
UI_MESSAGING = Hash("ui_messaging", host=redis_persistent)
CLASSIFICATION_ALIASES = Hash("classification_aliases", host=redis_persistent)

# Traffic queues
SUBMISSION_TRAFFIC = CommsQueue('submissions', host=redis)

# Replay queues
REPLAY_ALERT_QUEUE = NamedQueue("replay_alert", host=redis)
REPLAY_FILE_QUEUE = NamedQueue("replay_file", host=redis)
REPLAY_SUBMISSION_QUEUE = NamedQueue("replay_submission", host=redis)
REPLAY_CHECKPOINT_HASH = Hash("replay_checkpoint", host=redis_persistent)

# Update OIDC config using discovery url if exist
for oauth_provider in config.auth.oauth.providers:
    old_config = config.auth.oauth.providers[oauth_provider]
    if old_config.openid_connect_discovery_url:
        config.auth.oauth.providers[oauth_provider] = load_openid_configuration(
            old_config, old_config.openid_connect_discovery_url
        )


def get_token_store(key, token_type):
    return ExpiringSet(f"auth_token_{key}_{token_type}", host=redis, ttl=60 * 2)


def get_reset_queue(key):
    return ExpiringSet(f"reset_id_{key}", host=redis, ttl=60 * 15)


def get_signup_queue(key):
    return ExpiringSet(f"signup_id_{key}", host=redis, ttl=60 * 15)


# End of Configuration
#################################################################

#################################################################
# Prepare loggers
config.logging.log_to_console = config.logging.log_to_console or DEBUG
al_log.init_logging("ui", config=config)

AUDIT_KW_TARGET = ["sid",
                   "sha256",
                   "copy_sid",
                   "filter",
                   "filters",
                   "query",
                   "username",
                   "group",
                   "rev",
                   "index",
                   "cache_key",
                   "alert_key",
                   "alert_id",
                   "url",
                   "q",
                   "fq",
                   "file_hash",
                   "heuristic_id",
                   "error_key",
                   "config_name",
                   "servicename",
                   "service_name",
                   "qhash",
                   "enabled",
                   "is_active",
                   "submission_id",
                   "doc_id"]

AUDIT_LOG = logging.getLogger('assemblyline.ui.audit')
LOGGER = logging.getLogger('assemblyline.ui')

if AUDIT:
    AUDIT_LOG.setLevel(logging.INFO)

if DEBUG and config.logging.log_to_file:
    if not os.path.exists(config.logging.log_directory):
        os.makedirs(config.logging.log_directory)

    fh = logging.FileHandler(os.path.join(config.logging.log_directory, 'alui_audit.log'))
    fh.setLevel(logging.INFO)
    fh.setFormatter(logging.Formatter(AL_LOG_FORMAT))
    AUDIT_LOG.addHandler(fh)

AUDIT_LOG.debug('Audit logger ready!')
LOGGER.debug('Logger ready!')

# End of prepare logger
#################################################################

#################################################################
# Global instances
APPS_LIST = forge.CachedObject(get_apps_list, refresh=3600)
FILESTORE: FileStore = forge.get_filestore(config=config)
if config.datastore.archive.enabled:
    ARCHIVESTORE: FileStore = forge.get_archivestore(config=config)
else:
    ARCHIVESTORE = None
STORAGE: AssemblylineDatastore = forge.get_datastore(config=config, archive_access=True)
CACHE: Cache = Cache(prefix="flask_cache", host=redis, ttl=24 * 60 * 60)
AI_AGENT: AIAgentPool = get_ai_agent(config, LOGGER, STORAGE, CLASSIFICATION)
metadata_validator = MetadataValidator(STORAGE, METADATA_SUGGESTIONS)
IDENTIFY: Identify = forge.get_identify(config=config, datastore=STORAGE, use_cache=True)
ARCHIVE_MANAGER: ArchiveManager = ArchiveManager(
    config=config, datastore=STORAGE, filestore=FILESTORE, identify=IDENTIFY)
SERVICE_LIST = forge.CachedObject(STORAGE.list_all_services, kwargs=dict(as_obj=False, full=True))
SUBMISSION_PROFILES = {profile.name: profile for profile in config.submission.profiles}

# End global
#################################################################
