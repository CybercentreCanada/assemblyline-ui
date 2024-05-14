from assemblyline.common.str_utils import safe_str
from assemblyline.odm.models.config import AIFunctionParameters, AIConnection
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
    def __init__(self, config: AIConnection, function_params: AIFunctionParameters, logger) -> None:
        super(CohereAgent, self).__init__(config, function_params, logger)
        self.session = requests.Session()
        self.session.headers = self.config.headers
        self.session.proxies = self.config.proxies
        self.params.assistant.options = {k: v for k, v in self.params.assistant.options.items() if k in ALLOWED_OPTIONS}
        self.params.code.options = {k: v for k, v in self.params.code.options.items() if k in ALLOWED_OPTIONS}
        self.params.detailed_report.options = {k: v for k,
                                               v in self.params.detailed_report.options.items() if k in ALLOWED_OPTIONS}
        self.params.executive_summary.options = {
            k: v for k, v in self.params.executive_summary.options.items() if k in ALLOWED_OPTIONS}

        self.extra_context = "Please answer using only the information provided to you in the prompt. If there is " \
                             "not enough information in the prompt to answer the user's question, please say so. " \
                             "Please do NOT use any information you know about Assemblyline unless it is " \
                             "provided to you."

    def _call_ai_backend(self, data, action, with_trace=False):
        try:
            # Call API
            resp = self.session.post(self.config.chat_url, json=data)
        except Exception as e:
            message = f"An exception occured while trying to {action} with AI on " \
                      f"server {self.config.chat_url} with model {self.config.model_name}. [{e}]"
            self.logger.warning(message)
            raise APIException(message)

        if not resp.ok:
            msg_data = resp.json()
            msg = msg_data.get('message', None) or msg_data
            message = f"The AI model {self.config.model_name} denied the request " \
                      f"to {action} with the following message: {msg}"
            self.logger.warning(message)
            raise APIException(message)

        # Get AI response
        response_data = resp.json()
        content = response_data['text']
        reason = response_data['finish_reason']

        if reason.startswith("ERROR"):
            message = f"The AI model {self.config.model_name} denied the request " \
                      f"to {action} with the following message: {content}"
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

    def continued_ai_conversation(self, messages, lang="english"):
        # Get current values from openai message format
        preamble, history, message = self._openai_to_cohere_messages(messages)
        default_assistant_preamble = self._get_system_message(self.params.assistant.system_message, lang)

        # Build chat completions request
        data = {
            "max_tokens": self.params.assistant.max_tokens,
            'preamble': preamble or default_assistant_preamble,
            "message": message or "Hello!",
            "chat_history": history,
            "model": self.config.model_name,
            "stream": False
        }

        if not preamble or preamble == default_assistant_preamble:
            data["documents"] = [{"title": "Glossary of Assemblyline terms", "snippet": self.system_prompt}]

        data.update(self.params.assistant.options)

        return self._call_ai_backend(data, "answer the question", with_trace=True)

    def detailed_al_submission(self, report, lang="english", with_trace=False):
        # Build chat completions request
        preamble = self._get_system_message(self.params.detailed_report.system_message, lang)
        content = [self.params.detailed_report.task, "## Assemblyline Report\n", f"```yaml\n{yaml.dump(report)}\n```"]
        data = {
            "max_tokens": self.params.detailed_report.max_tokens,
            "preamble": preamble,
            "message": "\n".join(content),
            "model": self.config.model_name,
            "stream": False,
        }
        data.update(self.params.detailed_report.options)

        return self._call_ai_backend(data, "create detailed analysis of the AL report", with_trace=with_trace)

    def summarized_al_submission(self, report, lang="english", with_trace=False):
        # Build chat completions request
        preamble = self._get_system_message(self.params.executive_summary.system_message, lang)
        content = [self.params.executive_summary.task, "## Assemblyline Report\n", f"```yaml\n{yaml.dump(report)}\n```"]
        data = {
            "max_tokens": self.params.executive_summary.max_tokens,
            "preamble": preamble,
            "message": "\n".join(content),
            "model": self.config.model_name,
            "stream": False
        }
        data.update(self.params.executive_summary.options)

        return self._call_ai_backend(data, "summarize the AL report", with_trace=with_trace)

    def summarize_code_snippet(self, code, lang="english", with_trace=False):
        # Build chat completions request
        preamble = self._get_system_message(self.params.code.system_message, lang)
        content = [self.params.code.task, "## Code snippet\n", f"```\n{safe_str(code)}\n```"]
        data = {
            "max_tokens": self.params.code.max_tokens,
            "preamble": preamble,
            "message": "\n".join(content),
            "model": self.config.model_name,
            "stream": False
        }
        data.update(self.params.code.options)

        return self._call_ai_backend(data, "summarize code snippet", with_trace=with_trace)
