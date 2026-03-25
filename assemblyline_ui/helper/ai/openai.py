from copy import deepcopy
from urllib.parse import urlparse

import requests
import yaml
from assemblyline.common.str_utils import safe_str
from assemblyline.odm.models.config import AIConnection, AIFunctionParameters
from azure.identity import DefaultAzureCredential

from assemblyline_ui.helper.ai.base import AIAgent, APIException, EmptyAIResponse

ALLOWED_OPTIONS = ["temperature", "frequency_penalty", "presence_penalty", "top_p", "seed", "reasoning_effort"]


class OpenAIAgent(AIAgent):
    def __init__(self, config: AIConnection, function_params: AIFunctionParameters, logger) -> None:
        super(OpenAIAgent, self).__init__(config, function_params, logger)
        self.session = requests.Session()
        self.session.headers = self.config.headers
        if config.use_fic and "openai.azure.com" in config.chat_url:
            try:
                credentials = DefaultAzureCredential()
                aad_token = credentials.get_token('https://cognitiveservices.azure.com/.default').token
                self.config.headers['Authorization'] = f"Bearer {aad_token}"
            except Exception as e:
                logger.error(f"Could not properly initialize OpenAI Agent using Federated Identity token: {e}")
        self.session.proxies = self.config.proxies
        self.params.assistant.options = {k: v for k, v in self.params.assistant.options.items() if k in ALLOWED_OPTIONS}
        self.params.code.options = {k: v for k, v in self.params.code.options.items() if k in ALLOWED_OPTIONS}
        self.params.detailed_report.options = {k: v for k,
                                               v in self.params.detailed_report.options.items() if k in ALLOWED_OPTIONS}
        self.params.executive_summary.options = {
            k: v for k, v in self.params.executive_summary.options.items() if k in ALLOWED_OPTIONS}

    def _uses_responses_api(self):
        path = urlparse(self.config.chat_url).path.lower()
        return path.endswith("/responses") or "/responses/" in path

    def _uses_reasoning_tokens(self):
        model_name = (self.config.model_name or "").lower()
        return model_name.startswith(("gpt-5", "o1", "o3", "o4"))

    def _extract_text_content(self, content):
        if isinstance(content, str):
            return content

        if not isinstance(content, list):
            return ""

        text_parts = []
        for item in content:
            if not isinstance(item, dict):
                continue

            if item.get("type") not in ["output_text", "text"]:
                continue

            text_value = item.get("text", "")
            if isinstance(text_value, dict):
                text_value = text_value.get("value", "")

            if text_value:
                text_parts.append(text_value)

        return "".join(text_parts)

    def _extract_responses_content(self, response_data):
        output_text = response_data.get("output_text", "")
        if output_text:
            return output_text

        output = response_data.get("output", [])
        for item in output:
            if item.get("type") != "message":
                continue

            content = self._extract_text_content(item.get("content", []))
            if content:
                return content

        return ""

    def _is_response_truncated(self, response_data):
        if response_data.get("status") != "incomplete":
            return False

        details = response_data.get("incomplete_details") or {}
        return details.get("reason") == "max_output_tokens"

    def _build_chat_completions_request(self, messages, max_tokens, options):
        data = {
            "messages": deepcopy(messages),
            "model": self.config.model_name,
            "stream": False
        }
        if self._uses_reasoning_tokens():
            data["max_completion_tokens"] = max_tokens
        else:
            data["max_tokens"] = max_tokens
        data.update(deepcopy(options))
        return data

    def _build_responses_request(self, messages, max_tokens, options):
        input_messages = deepcopy(messages)
        instructions = None

        if input_messages and input_messages[0]["role"] == "system":
            instructions = input_messages.pop(0).get("content") or None

        if not input_messages:
            input_messages = [{"role": "user", "content": "Hello"}]

        data = {
            "input": input_messages,
            "max_output_tokens": max_tokens,
            "model": self.config.model_name,
            "stream": False
        }
        if instructions:
            data["instructions"] = instructions

        request_options = deepcopy(options)
        reasoning_effort = request_options.pop("reasoning_effort", None)
        if reasoning_effort:
            data["reasoning"] = {"effort": reasoning_effort}

        data.update(request_options)
        return data

    def _build_request(self, messages, max_tokens, options):
        if self._uses_responses_api():
            return self._build_responses_request(messages, max_tokens, options)
        return self._build_chat_completions_request(messages, max_tokens, options)

    def _call_ai_backend(self, data, action, with_trace=False, trace_messages=None):
        try:
            # Call API
            resp = self.session.post(self.config.chat_url, json=data)
        except Exception as e:
            message = f"An exception occured while trying to {action} with AI on " \
                      f"server {self.config.chat_url} with model {self.config.model_name}. [{e}]"
            self.logger.warning(message)
            raise APIException(message)

        if not resp.ok:
            try:
                msg_data = resp.json()
            except ValueError:
                msg_data = resp.text
            if isinstance(msg_data, dict):
                msg = msg_data.get('error', {}).get('message', None) or msg_data
            else:
                msg = msg_data
            message = f"The AI model {self.config.model_name} denied the request to " \
                      f"{action} with the following message: {msg}"
            self.logger.warning(message)
            raise APIException(message)

        response_data = resp.json()

        if self._uses_responses_api():
            content = self._extract_responses_content(response_data)
            truncated = self._is_response_truncated(response_data)
        else:
            responses = response_data.get('choices', [])
            if not responses:
                raise EmptyAIResponse("There was no response returned by the AI")

            content = self._extract_text_content(responses[0]['message']['content'])
            truncated = responses[0]['finish_reason'] == 'length'

        if content:
            if with_trace:
                trace = deepcopy(trace_messages or data.get('messages', []))
                trace.append({'role': 'assistant', 'content': content})
                return {'trace': trace, 'truncated': truncated}
            return {'content': content, 'truncated': truncated}

        raise EmptyAIResponse("There was no response returned by the AI")

    def continued_ai_conversation(self, messages, lang="english"):
        # If there are no system prompt, use the default one.
        if not messages[0]['content'] and messages[0]['role'] == 'system':
            system_message = self._get_system_message(self.params.assistant.system_message, lang)
            messages[0]['content'] = "\n".join([system_message, self.system_prompt])

        # Make sure this is not an empty message
        messages[-1]['content'] = messages[-1]['content'] or "Hello"

        # Build chat completions request
        data = self._build_request(messages, self.params.assistant.max_tokens, self.params.assistant.options)

        return self._call_ai_backend(data, "answer the question", with_trace=True, trace_messages=messages)

    def detailed_al_submission(self, report, lang="english", with_trace=False):
        # Build chat completions request
        system_message = self._get_system_message(self.params.detailed_report.system_message, lang)
        content = [self.params.detailed_report.task, "## Assemblyline Report\n", f"```yaml\n{yaml.dump(report)}\n```"]
        messages = [
            {"role": "system", "content": "\n".join(
                [system_message, self.definition_prompt, "", self.scoring_prompt])},
            # TODO: we may have to do token detection and split the data in chunks...
            {"role": "user",
                "content": "\n".join(content)},
        ]
        data = self._build_request(messages, self.params.detailed_report.max_tokens, self.params.detailed_report.options)

        return self._call_ai_backend(
            data, "create detailed analysis of the AL report", with_trace=with_trace, trace_messages=messages)

    def summarized_al_submission(self, report, lang="english", with_trace=False):
        # Build chat completions request
        system_message = self._get_system_message(self.params.executive_summary.system_message, lang)
        content = [self.params.executive_summary.task, "## Assemblyline Report\n", f"```yaml\n{yaml.dump(report)}\n```"]
        messages = [
            {"role": "system", "content": "\n".join(
                [system_message, self.definition_prompt, "", self.scoring_prompt])},
            # TODO: we may have to do token detection and split the data in chunks...
            {"role": "user", "content": "\n".join(content)},
        ]
        data = self._build_request(
            messages, self.params.executive_summary.max_tokens, self.params.executive_summary.options)

        return self._call_ai_backend(data, "summarize the AL report", with_trace=with_trace, trace_messages=messages)

    def summarize_code_snippet(self, code, lang="english", with_trace=False):
        # Build chat completions request
        system_message = self._get_system_message(self.params.code.system_message, lang)
        content = [self.params.code.task, "## Code snippet\n", f"```\n{safe_str(code)}\n```"]
        messages = [
            {"role": "system", "content": system_message},
            # TODO: we may have to do token detection and split the data in chunks...
            {"role": "user", "content": "\n".join(content)}
        ]
        data = self._build_request(messages, self.params.code.max_tokens, self.params.code.options)

        return self._call_ai_backend(data, "summarize code snippet", with_trace=with_trace, trace_messages=messages)
