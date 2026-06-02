import json
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
            msg = msg_data.get('error', {}).get('message', None) or msg_data
            message = f"The AI model {self.config.model_name} denied the request to " \
                      f"{action} with the following message: {msg}"
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

    def continued_ai_conversation(self, messages, lang="english"):
        # If there are no system prompt, use the default one.
        if not messages[0]['content'] and messages[0]['role'] == 'system':
            system_message = self._get_system_message(self.params.assistant.system_message, lang)
            messages[0]['content'] = "\n".join([system_message, self.system_prompt])

        # Make sure this is not an empty message
        messages[-1]['content'] = messages[-1]['content'] or "Hello"

        # Build chat completions request
        data = {
            "max_tokens": self.params.assistant.max_tokens,
            "messages": messages,
            "model": self.config.model_name,
            "stream": False
        }
        data.update(self.params.assistant.options)

        return self._call_ai_backend(data, "answer the question", with_trace=True)

    def detailed_al_submission(self, report, lang="english", with_trace=False):
        # Build chat completions request
        system_message = self._get_system_message(self.params.detailed_report.system_message, lang)
        content = [self.params.detailed_report.task, "## Assemblyline Report\n", f"```yaml\n{yaml.dump(report)}\n```"]
        data = {
            "max_tokens": self.params.detailed_report.max_tokens,
            "messages": [
                {"role": "system", "content": "\n".join(
                    [system_message, self.definition_prompt, "", self.scoring_prompt])},
                # TODO: we may have to do token detection and split the data in chunks...
                {"role": "user",
                    "content": "\n".join(content)},
            ],
            "model": self.config.model_name,
            "stream": False
        }
        data.update(self.params.detailed_report.options)

        return self._call_ai_backend(data, "create detailed analysis of the AL report", with_trace=with_trace)

    def summarized_al_submission(self, report, lang="english", with_trace=False):
        # Build chat completions request
        system_message = self._get_system_message(self.params.executive_summary.system_message, lang)
        content = [self.params.executive_summary.task, "## Assemblyline Report\n", f"```yaml\n{yaml.dump(report)}\n```"]
        data = {
            "max_tokens": self.params.executive_summary.max_tokens,
            "messages": [
                {"role": "system", "content": "\n".join(
                    [system_message, self.definition_prompt, "", self.scoring_prompt])},
                # TODO: we may have to do token detection and split the data in chunks...
                {"role": "user", "content": "\n".join(content)},
            ],
            "model": self.config.model_name,
            "stream": False
        }
        data.update(self.params.executive_summary.options)

        return self._call_ai_backend(data, "summarize the AL report", with_trace=with_trace)

    def summarize_code_snippet(self, code, lang="english", with_trace=False):
        # Build chat completions request
        system_message = self._get_system_message(self.params.code.system_message, lang)
        content = [self.params.code.task, "## Code snippet\n", f"```\n{safe_str(code)}\n```"]
        data = {
            "max_tokens": self.params.code.max_tokens,
            "messages": [
                {"role": "system", "content": system_message},
                # TODO: we may have to do token detection and split the data in chunks...
                {"role": "user", "content": "\n".join(content)}
            ],
            "model": self.config.model_name,
            "stream": False
        }
        data.update(self.params.code.options)

        return self._call_ai_backend(data, "summarize code snippet", with_trace=with_trace)

    def agentic_conversation(self, messages, tools_openai, tool_registry, agent_profile, user=None, lang="english"):
        """Run an agentic conversation loop with tool calling.

        Args:
            messages: Conversation message history
            tools_openai: Tool definitions in OpenAI function-calling format
            tool_registry: ToolRegistry instance for executing tool calls
            agent_profile: AIAgentProfile with max_iterations, max_tokens, options
            user: Current user dict for access control
            lang: Response language

        Returns:
            dict with 'trace' (full message history) and 'truncated' flag
        """
        max_iterations = agent_profile.max_iterations
        options = {k: v for k, v in (agent_profile.options or {}).items() if k in ALLOWED_OPTIONS}

        for iteration in range(max_iterations):
            # Build request with tools
            data = {
                "max_tokens": agent_profile.max_tokens,
                "messages": messages,
                "model": self.config.model_name,
                "stream": False,
            }
            if tools_openai:
                data["tools"] = tools_openai
                data["tool_choice"] = "auto"
            data.update(options)

            # Call the LLM
            try:
                resp = self.session.post(self.config.chat_url, json=data)
            except Exception as e:
                raise APIException(f"Agentic call failed on iteration {iteration}: {e}")

            if not resp.ok:
                msg_data = resp.json()
                msg = msg_data.get('error', {}).get('message', None) or msg_data
                raise APIException(f"Agentic call denied on iteration {iteration}: {msg}")

            choices = resp.json().get('choices', [])
            if not choices:
                raise EmptyAIResponse("No response from AI during agentic loop")

            message = choices[0]['message']
            finish_reason = choices[0].get('finish_reason', 'stop')

            # If the LLM wants to call tools, execute them and continue
            tool_calls = message.get('tool_calls')
            if tool_calls and finish_reason == 'tool_calls':
                # Append the assistant message with tool_calls to the trace
                messages.append({
                    'role': 'assistant',
                    'content': message.get('content'),
                    'tool_calls': tool_calls,
                })

                # Execute each tool call and append results
                for tool_call in tool_calls:
                    func = tool_call.get('function', {})
                    tool_name = func.get('name', '')
                    try:
                        tool_args = json.loads(func.get('arguments', '{}'))
                    except json.JSONDecodeError:
                        tool_args = {}

                    self.logger.info(f"Agentic tool call [{iteration}]: {tool_name}({tool_args})")

                    tool_result = tool_registry.execute_tool(tool_name, tool_args, user=user)

                    messages.append({
                        'role': 'tool',
                        'tool_call_id': tool_call.get('id', ''),
                        'content': tool_result,
                    })

                continue  # Next iteration — let LLM process tool results

            # No tool calls — final response
            content = message.get('content', '')
            messages.append({'role': 'assistant', 'content': content})
            return {'trace': messages, 'truncated': finish_reason == 'length'}

        # Exhausted iterations — return what we have
        messages.append({
            'role': 'assistant',
            'content': '[Agent reached maximum iteration limit. Returning partial results.]'
        })
        return {'trace': messages, 'truncated': True}
