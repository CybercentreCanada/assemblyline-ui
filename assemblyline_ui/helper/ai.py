import requests
import yaml

from assemblyline_ui.config import config, LOGGER


class AiApiException(Exception):
    pass


def _call_ai_backend(data, system_message, action):
    # Build chat completions request
    data = {
        "max_tokens": config.ui.ai.max_tokens,
        "messages": [
            {"role": "system", "content": system_message},
            {"role": "user", "content": data},
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
        message = f"An exception occured while trying to {action} with AI on server {config.ui.ai.chat_url}. [{e}]"
        LOGGER.warning(message)
        raise AiApiException(message)

    if not resp.ok:
        message = f"The AI API denied the request to {action} with the following message: {resp.json()}"
        LOGGER.warning(message)
        raise AiApiException(message)

    return resp.json()


def summarized_al_submission(report):
    return _call_ai_backend(yaml.dump(report), config.ui.ai.report_system_message, "summarize the AL report")


def summarize_code_snippet(code):
    return _call_ai_backend(code, config.ui.ai.code_system_message, "summarize code snippet")
