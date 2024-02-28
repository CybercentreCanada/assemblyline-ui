from assemblyline.common.str_utils import safe_str
import requests
import yaml

from assemblyline_ui.config import config, LOGGER


class APIException(Exception):
    pass


class EmptyAIResponse(Exception):
    pass


def _call_ai_backend(data, action, with_trace=False):
    try:
        # Call API
        resp = requests.post(config.ui.ai.chat_url, headers=config.ui.ai.headers,
                             proxies=config.ui.ai.proxies, json=data)
    except Exception as e:
        message = f"An exception occured while trying to {action} with AI on server {config.ui.ai.chat_url}. [{e}]"
        LOGGER.warning(message)
        raise APIException(message)

    if not resp.ok:
        msg_data = resp.json()
        msg = msg_data.get('error', {}).get('message', None) or msg_data
        message = f"The AI API denied the request to {action} with the following message: {msg}"
        LOGGER.warning(message)
        raise APIException(message)

    # Get AI responses
    responses = resp.json()['choices']
    if responses:
        content = responses[0]['message']['content']
        reason = responses[0]['finish_reason']
        if with_trace:
            trace = data['messages']
            trace.append({'role': 'assistant', 'content': content})
            return {'trace': trace, 'truncated': reason == 'length'}
        return {'content': content, 'truncated': reason == 'length'}

    raise EmptyAIResponse("There was no response returned by the AI")


def continued_ai_conversation(messages):
    # Build chat completions request
    data = {
        "max_tokens": config.ui.ai.assistant.max_tokens,
        "messages": messages,
        "model": config.ui.ai.model_name,
        "stream": False
    }
    data.update(config.ui.ai.assistant.options)

    return _call_ai_backend(data, "answer the question", with_trace=True)


def detailed_al_submission(report, lang="english", with_trace=False):
    # Build chat completions request
    data = {
        "max_tokens": config.ui.ai.detailed_report.max_tokens,
        "messages": [
            {"role": "system", "content": config.ui.ai.detailed_report.system_message.replace("$(LANG)", lang)},
            # TODO: we may have to do token detection and split the data in chunks...
            {"role": "user", "content": yaml.dump(report)},
        ],
        "model": config.ui.ai.model_name,
        "stream": False
    }
    data.update(config.ui.ai.detailed_report.options)

    return _call_ai_backend(data, "create detailed analysis of the AL report", with_trace=with_trace)


def summarized_al_submission(report, lang="english", with_trace=False):
    # Build chat completions request
    data = {
        "max_tokens": config.ui.ai.executive_summary.max_tokens,
        "messages": [
            {"role": "system", "content": config.ui.ai.executive_summary.system_message.replace("$(LANG)", lang)},
            # TODO: we may have to do token detection and split the data in chunks...
            {"role": "user", "content": yaml.dump(report)},
        ],
        "model": config.ui.ai.model_name,
        "stream": False
    }
    data.update(config.ui.ai.executive_summary.options)

    return _call_ai_backend(data, "summarize the AL report", with_trace=with_trace)


def summarize_code_snippet(code, lang="english", with_trace=False):
    # Build chat completions request
    data = {
        "max_tokens": config.ui.ai.code.max_tokens,
        "messages": [
            {"role": "system", "content": config.ui.ai.code.system_message.replace("$(LANG)", lang)},
            # TODO: we may have to do token detection and split the data in chunks...
            {"role": "user", "content": safe_str(code)},
        ],
        "model": config.ui.ai.model_name,
        "stream": False
    }
    data.update(config.ui.ai.code.options)

    return _call_ai_backend(data, "summarize code snippet", with_trace=with_trace)
