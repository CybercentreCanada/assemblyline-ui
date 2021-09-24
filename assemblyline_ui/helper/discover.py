import logging
import requests

from assemblyline.common import forge
config = forge.get_config()
logger = logging.getLogger('assemblyline.ui')


def get_apps_list():
    apps = {'apps': []}
    if config.ui.discover_url:
        try:
            resp = requests.get(config.ui.discover_url, headers={'accept': 'application/json'}, timeout=5)
            if resp.ok:
                data = resp.json()
                for app in data['applications']['application']:
                    try:
                        url = app['instance'][0]['hostName']

                        if config.ui.fqdn not in url:
                            apps['apps'].append(
                                {
                                    "alt": app['instance'][0]['metadata']['alternateText'],
                                    "name": app['name'],
                                    "img_d": app['instance'][0]['metadata']['imageDark'],
                                    "img_l": app['instance'][0]['metadata']['imageLight'],
                                    "route": url,
                                    "classification": app['instance'][0]['metadata']['classification']
                                }
                            )
                    except Exception:
                        logger.exception(f'Failed to parse get app: {str(app)}')
            else:
                logger.warning(f'Invalid response from server for apps discovery: {config.ui.discover_url}')
        except Exception:
            logger.exception(f'Failed to get apps from discover URL: {config.ui.discover_url}')

    apps['apps'] = sorted(apps['apps'], key=lambda k: k['name'])
    return apps
