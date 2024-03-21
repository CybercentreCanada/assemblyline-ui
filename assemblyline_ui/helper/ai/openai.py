from assemblyline.common.str_utils import safe_str
from assemblyline.odm.models.config import AI as AIConfig
from assemblyline_ui.helper.ai.base import AIAgent, APIException, EmptyAIResponse
import requests
import yaml

ALLOWED_OPTIONS = ["temperature", "frequency_penalty", "presence_penalty", "top_p", "seed"]


class OpenAIAgent(AIAgent):
    def __init__(self, config: AIConfig, logger) -> None:
        super(OpenAIAgent, self).__init__(config, logger)
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
            msg = msg_data.get('error', {}).get('message', None) or msg_data
            message = f"The AI API denied the request to {action} with the following message: {msg}"
            self.logger.warning(message)
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

    def continued_ai_conversation(self, messages):
        # Make sure this is not an empty message
        messages[-1]['content'] = messages[-1]['content'] or "Hello"

        # Build chat completions request
        data = {
            "max_tokens": self.config.assistant.max_tokens,
            "messages": messages,
            "model": self.config.model_name,
            "stream": False
        }
        data.update(self.config.assistant.options)

        return self._call_ai_backend(data, "answer the question", with_trace=True)

    def detailed_al_submission(self, report, lang="english", with_trace=False):
        # Build chat completions request
        data = {
            "max_tokens": self.config.detailed_report.max_tokens,
            "messages": [
                {"role": "system", "content": self.config.detailed_report.system_message.replace(
                    "$(LANG)", lang)},
                # TODO: we may have to do token detection and split the data in chunks...
                {"role": "user", "content": yaml.dump(report)},
            ],
            "model": self.config.model_name,
            "stream": False
        }
        data.update(self.config.detailed_report.options)

        return self._call_ai_backend(data, "create detailed analysis of the AL report", with_trace=with_trace)

    def summarized_al_submission(self, report, lang="english", with_trace=False):
        # Build chat completions request
        data = {
            "max_tokens": self.config.executive_summary.max_tokens,
            "messages": [
                {"role": "system", "content": self.config.executive_summary.system_message.replace(
                    "$(LANG)", lang)},
                # TODO: we may have to do token detection and split the data in chunks...
                {"role": "user", "content": yaml.dump(report)},
            ],
            "model": self.config.model_name,
            "stream": False
        }
        data.update(self.config.executive_summary.options)

        return self._call_ai_backend(data, "summarize the AL report", with_trace=with_trace)

    def summarize_code_snippet(self, code, lang="english", with_trace=False):
        # Build chat completions request
        data = {
            "max_tokens": self.config.code.max_tokens,
            "messages": [
                {"role": "system", "content": self.config.code.system_message.replace("$(LANG)", lang)},
                # TODO: we may have to do token detection and split the data in chunks...
                {"role": "user", "content": safe_str(code)},
            ],
            "model": self.config.model_name,
            "stream": False
        }
        data.update(self.config.code.options)

        return self._call_ai_backend(data, "summarize code snippet", with_trace=with_trace)
