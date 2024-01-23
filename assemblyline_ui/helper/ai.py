import requests
import yaml

from assemblyline_ui.config import config, LOGGER


class AiApiException(Exception):
    pass


def get_ai_summarized_report(report):
    # Build chat completions request
    data = {
        "max_tokens": config.ui.ai.max_tokens,
        "messages": [
            {"role": "system", "content": config.ui.ai.report_system_message},
            {"role": "user", "content": yaml.dump(report)},
        ],
        "model": config.ui.ai.model_name,
        "stream": False
    }
    data.update(config.ui.ai.options)

    # Show request to AI Backend in debug mode
    if config.ui.debug:
        LOGGER.info(config.ui.ai.chat_url)
        LOGGER.info(config.ui.ai.headers)
        LOGGER.info(data)

    try:
        # Call API
        resp = requests.post(config.ui.ai.chat_url, headers=config.ui.ai.headers, json=data)
    except Exception as e:
        raise AiApiException(e)

    if not resp.ok:
        raise AiApiException(f"An exception occured while trying to sumarize the report with AI. ({resp.json()})")

    return resp.json()
