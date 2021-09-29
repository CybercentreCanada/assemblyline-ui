import logging
import os
import functools

from assemblyline.common.version import BUILD_MINOR, FRAMEWORK_VERSION, SYSTEM_VERSION
from assemblyline.common.logformat import AL_LOG_FORMAT
from assemblyline.common import forge, log as al_log
from assemblyline.remote.datatypes.hash import Hash
from assemblyline.remote.datatypes.queues.comms import CommsQueue
from assemblyline.remote.datatypes.set import ExpiringSet
from assemblyline.remote.datatypes.user_quota_tracker import UserQuotaTracker
from assemblyline_ui.helper.discover import get_apps_list

config = forge.get_config()

#################################################################
# Configuration

CLASSIFICATION = forge.get_classification()

ALLOW_RAW_DOWNLOADS = config.ui.allow_raw_downloads
APP_ID = "https://%s" % config.ui.fqdn
APP_NAME = "Assemblyline"
AUDIT = config.ui.audit

SECRET_KEY = config.ui.secret_key
DEBUG = config.ui.debug
DOWNLOAD_ENCODING = config.ui.download_encoding
MAX_CLASSIFICATION = CLASSIFICATION.UNRESTRICTED
ORGANISATION = config.system.organisation
SYSTEM_TYPE = config.system.type
VERSION = os.environ.get('ASSEMBLYLINE_VERSION', f"{FRAMEWORK_VERSION}.{SYSTEM_VERSION}.{BUILD_MINOR}.dev0")

BUNDLING_DIR = "/var/lib/assemblyline/bundling"

TEMP_DIR = "/var/lib/assemblyline/flowjs/"
TEMP_SUBMIT_DIR = "/var/lib/assemblyline/submit/"

QUOTA_TRACKER = UserQuotaTracker('quota', timeout=60 * 2,  # 2 Minutes timout
                                 host=config.core.redis.nonpersistent.host,
                                 port=config.core.redis.nonpersistent.port)

SUBMISSION_TRACKER = UserQuotaTracker('submissions', timeout=60 * 60,  # 60 minutes timout
                                      host=config.core.redis.persistent.host,
                                      port=config.core.redis.persistent.port)

KV_SESSION = Hash("flask_sessions",
                  host=config.core.redis.nonpersistent.host,
                  port=config.core.redis.nonpersistent.port)

UI_MESSAGING = Hash("ui_messaging",
                    host=config.core.redis.persistent.host,
                    port=config.core.redis.persistent.port)


@functools.lru_cache()
def get_submission_traffic_channel():
    return CommsQueue('submissions',
                      host=config.core.redis.nonpersistent.host,
                      port=config.core.redis.nonpersistent.port)


def get_token_store(key):
    return ExpiringSet(f"oauth_token_{key}",
                       host=config.core.redis.nonpersistent.host,
                       port=config.core.redis.nonpersistent.port,
                       ttl=60 * 2)


def get_reset_queue(key):
    return ExpiringSet(f"reset_id_{key}",
                       host=config.core.redis.nonpersistent.host,
                       port=config.core.redis.nonpersistent.port,
                       ttl=60 * 15)


def get_signup_queue(key):
    return ExpiringSet(f"signup_id_{key}",
                       host=config.core.redis.nonpersistent.host,
                       port=config.core.redis.nonpersistent.port,
                       ttl=60 * 15)


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
                   "query",
                   "username",
                   "group",
                   "rev",
                   "wq_id",
                   "bucket",
                   "cache_key",
                   "alert_key",
                   "alert_id",
                   "url",
                   "q",
                   "fq",
                   "file_hash",
                   "heuristic_id",
                   "error_key",
                   "mac",
                   "vm_type",
                   "vm_name",
                   "config_name",
                   "servicename",
                   "vm"]

AUDIT_LOG = logging.getLogger('assemblyline.ui.audit')
LOGGER = logging.getLogger('assemblyline.ui')

if AUDIT:
    AUDIT_LOG.setLevel(logging.INFO)

if DEBUG:
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
STORAGE = forge.get_datastore(archive_access=True)
SERVICE_LIST = forge.CachedObject(STORAGE.list_all_services, kwargs=dict(as_obj=False, full=True))
# End global
#################################################################
