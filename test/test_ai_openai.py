import importlib
import sys
import types
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _install_assemblyline_stubs():
    assemblyline = types.ModuleType("assemblyline")
    common = types.ModuleType("assemblyline.common")
    forge = types.ModuleType("assemblyline.common.forge")
    log = types.ModuleType("assemblyline.common.log")
    str_utils = types.ModuleType("assemblyline.common.str_utils")
    odm = types.ModuleType("assemblyline.odm")
    models = types.ModuleType("assemblyline.odm.models")
    config = types.ModuleType("assemblyline.odm.models.config")
    service = types.ModuleType("assemblyline.odm.models.service")
    azure = types.ModuleType("azure")
    azure_identity = types.ModuleType("azure.identity")

    forge.get_datastore = lambda *args, **kwargs: None
    forge.get_classification = lambda *args, **kwargs: None

    class PrintLogger:
        def warning(self, *args, **kwargs):
            pass

        def error(self, *args, **kwargs):
            pass

    class DefaultAzureCredential:
        def get_token(self, *_args, **_kwargs):
            return SimpleNamespace(token="token")

    log.PrintLogger = PrintLogger
    str_utils.safe_str = lambda value: value
    config.AIConnection = object
    config.AIFunctionParameters = object
    config.Config = object
    service.Service = object
    azure_identity.DefaultAzureCredential = DefaultAzureCredential

    modules = {
        "assemblyline": assemblyline,
        "assemblyline.common": common,
        "assemblyline.common.forge": forge,
        "assemblyline.common.log": log,
        "assemblyline.common.str_utils": str_utils,
        "assemblyline.odm": odm,
        "assemblyline.odm.models": models,
        "assemblyline.odm.models.config": config,
        "assemblyline.odm.models.service": service,
        "azure": azure,
        "azure.identity": azure_identity,
    }

    sys.modules.update(modules)


def _load_openai_agent():
    _install_assemblyline_stubs()
    for name in list(sys.modules):
        if name.startswith("assemblyline_ui.helper.ai"):
            sys.modules.pop(name)

    module = importlib.import_module("assemblyline_ui.helper.ai.openai")
    return module.OpenAIAgent


class _FakeResponse:
    def __init__(self, payload, ok=True):
        self._payload = payload
        self.ok = ok
        self.text = str(payload)

    def json(self):
        return self._payload


class _FakeSession:
    def __init__(self, payload, ok=True):
        self.payload = payload
        self.ok = ok
        self.headers = {}
        self.proxies = {}
        self.calls = []

    def post(self, url, json):
        self.calls.append((url, json))
        return _FakeResponse(self.payload, ok=self.ok)


def _make_function_params(options=None):
    options = options or {}

    def params(max_tokens):
        return SimpleNamespace(max_tokens=max_tokens, options=dict(options), system_message="System prompt", task="Task")

    return SimpleNamespace(
        assistant=params(111),
        code=params(222),
        detailed_report=params(333),
        executive_summary=params(444),
    )


def _make_agent(chat_url, model_name, response_payload, options=None):
    OpenAIAgent = _load_openai_agent()
    config = SimpleNamespace(
        headers={},
        proxies={},
        use_fic=False,
        chat_url=chat_url,
        model_name=model_name,
    )
    agent = OpenAIAgent(config, _make_function_params(options=options), logger=SimpleNamespace(
        warning=lambda *args, **kwargs: None,
        error=lambda *args, **kwargs: None,
    ))
    agent.session = _FakeSession(response_payload)
    return agent


def test_gpt5_chat_completions_uses_max_completion_tokens():
    agent = _make_agent(
        "https://api.openai.com/v1/chat/completions",
        "gpt-5",
        {"choices": [{"message": {"content": "Answer"}, "finish_reason": "stop"}]},
        options={"reasoning_effort": "medium", "temperature": 0.1, "unsupported": "drop-me"},
    )

    result = agent.continued_ai_conversation([
        {"role": "system", "content": "System"},
        {"role": "user", "content": "Hello"},
    ])

    _, payload = agent.session.calls[0]
    assert payload["max_completion_tokens"] == 111
    assert "max_tokens" not in payload
    assert payload["reasoning_effort"] == "medium"
    assert "unsupported" not in payload
    assert result["trace"][-1] == {"role": "assistant", "content": "Answer"}
    assert result["truncated"] is False


def test_legacy_chat_completions_keeps_max_tokens():
    agent = _make_agent(
        "https://api.openai.com/v1/chat/completions",
        "gpt-4o-mini",
        {"choices": [{"message": {"content": "Answer"}, "finish_reason": "length"}]},
    )

    result = agent.summarize_code_snippet("print('hello')")

    _, payload = agent.session.calls[0]
    assert payload["max_tokens"] == 222
    assert "max_completion_tokens" not in payload
    assert result["truncated"] is True


def test_responses_api_maps_instructions_and_reasoning_effort():
    agent = _make_agent(
        "https://api.openai.com/v1/responses",
        "gpt-5-codex",
        {
            "status": "incomplete",
            "incomplete_details": {"reason": "max_output_tokens"},
            "output": [{
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "Summary"}],
            }],
        },
        options={"reasoning_effort": "high", "temperature": 0.2},
    )

    messages = [
        {"role": "system", "content": "System"},
        {"role": "assistant", "content": "Previous answer"},
        {"role": "user", "content": "New question"},
    ]
    result = agent.continued_ai_conversation(messages)

    _, payload = agent.session.calls[0]
    assert payload["instructions"] == "System"
    assert payload["input"] == messages[1:]
    assert payload["max_output_tokens"] == 111
    assert payload["reasoning"] == {"effort": "high"}
    assert "reasoning_effort" not in payload
    assert "messages" not in payload
    assert result["trace"][-1] == {"role": "assistant", "content": "Summary"}
    assert result["truncated"] is True
