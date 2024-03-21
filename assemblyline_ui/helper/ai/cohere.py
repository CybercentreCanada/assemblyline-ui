from assemblyline.common.str_utils import safe_str
from assemblyline.odm.models.config import AI as AIConfig
from assemblyline_ui.helper.ai.base import AIAgent, APIException
import requests
import yaml

ALLOWED_OPTIONS = ["temperature", "frequency_penalty", "presence_penalty", "seed"]
ROLE_MAP = {
    "system": "SYSTEM",
    "user": "USER",
    "assistant": "CHATBOT",
    "SYSTEM": "system",
    "USER": "user",
    "CHATBOT": "assistant"
}


class CohereAgent(AIAgent):
    def __init__(self, config: AIConfig, logger) -> None:
        super(CohereAgent, self).__init__(config, logger)
        self.session = requests.Session()
        self.session.headers = self.config.headers
        self.session.proxies = self.config.proxies
        self.config.assistant.options = {k: v for k, v in self.config.assistant.options.items() if k in ALLOWED_OPTIONS}
        self.config.code.options = {k: v for k, v in self.config.code.options.items() if k in ALLOWED_OPTIONS}
        self.config.detailed_report.options = {k: v for k,
                                               v in self.config.detailed_report.options.items() if k in ALLOWED_OPTIONS}
        self.config.executive_summary.options = {
            k: v for k, v in self.config.executive_summary.options.items() if k in ALLOWED_OPTIONS}

    def _call_ai_backend(self, data, action, with_trace=False):
        try:
            # Call API
            resp = self.session.post(self.config.chat_url, json=data)
        except Exception as e:
            message = f"An exception occured while trying to {action} with AI on server {self.config.chat_url}. [{e}]"
            self.logger.warning(message)
            raise APIException(message)

        if not resp.ok:
            msg_data = resp.json()
            msg = msg_data.get('message', None) or msg_data
            message = f"The AI API denied the request to {action} with the following message: {msg}"
            self.logger.warning(message)
            raise APIException(message)

        # Get AI response
        response_data = resp.json()
        content = response_data['text']
        reason = response_data['finish_reason']

        if reason.startswith("ERROR"):
            message = f"The AI API denied the request to {action} with the following message: {content}"
            self.logger.warning(message)
            raise APIException(message)

        if with_trace:
            trace = [{"role": ROLE_MAP[message['role']], 'content': message['message']}
                     for message in response_data['chat_history']]
            preamble = data.get('preamble', None)
            if preamble:
                trace.insert(0, {'role': 'system', 'content': preamble})
            return {'trace': trace, 'truncated': reason == 'MAX_TOKENS'}
        return {'content': content, 'truncated': reason == 'MAX_TOKENS'}

    def _openai_to_cohere_messages(self, messages: list):
        preamble = None
        message = None

        if messages[0]['role'] == 'system':
            preamble = messages.pop(0)['content']
        message = messages.pop()['content']

        history = [{"role": ROLE_MAP[message['role']], 'message': message['content']} for message in messages]

        return preamble, history, message

    def continued_ai_conversation(self, messages):

        preamble, history, message = self._openai_to_cohere_messages(messages)
        # Build chat completions request
        data = {
            "max_tokens": self.config.assistant.max_tokens,
            "message": message or "Hello!",
            "history": history,
            "model": self.config.model_name,
            "stream": False
        }
        if preamble:
            data['preamble'] = preamble
        data.update(self.config.assistant.options)

        return self._call_ai_backend(data, "answer the question", with_trace=True)

    def detailed_al_submission(self, report, lang="english", with_trace=False):
        # Build chat completions request
        data = {
            "max_tokens": self.config.detailed_report.max_tokens,
            "preamble": self.config.detailed_report.system_message.replace("$(LANG)", lang),
            "message": yaml.dump(report),
            "model": self.config.model_name,
            "stream": False
        }
        data.update(self.config.detailed_report.options)

        return self._call_ai_backend(data, "create detailed analysis of the AL report", with_trace=with_trace)

    def summarized_al_submission(self, report, lang="english", with_trace=False):
        # Build chat completions request
        data = {
            "max_tokens": self.config.executive_summary.max_tokens,
            "preamble": self.config.executive_summary.system_message.replace("$(LANG)", lang),
            "message": yaml.dump(report),
            "model": self.config.model_name,
            "stream": False
        }
        data.update(self.config.executive_summary.options)

        return self._call_ai_backend(data, "summarize the AL report", with_trace=with_trace)

    def summarize_code_snippet(self, code, lang="english", with_trace=False):
        # Build chat completions request
        data = {
            "max_tokens": self.config.code.max_tokens,
            "preamble": self.config.code.system_message.replace("$(LANG)", lang),
            "message": safe_str(code),
            "model": self.config.model_name,
            "stream": False
        }
        data.update(self.config.code.options)

        return self._call_ai_backend(data, "summarize code snippet", with_trace=with_trace)
