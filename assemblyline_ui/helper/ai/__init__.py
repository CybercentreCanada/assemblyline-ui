from logging import Logger

from assemblyline.odm.models.config import AIConnection, AIFunctionParameters, Config
from assemblyline_ui.helper.ai.base import AIAgentPool
from assemblyline_ui.helper.ai.cohere import CohereAgent
from assemblyline_ui.helper.ai.openai import OpenAIAgent


def get_ai_agent(config: Config, logger: Logger, ds, classification):
    backends = []
    if config.ui.ai_backends.enabled:
        for api_connection in config.ui.ai_backends.api_connections:
            backends.append(_init_ai_agent(api_connection, config.ui.ai_backends.function_params, logger=logger))

    return AIAgentPool(config, api_backends=backends, logger=logger, ds=ds, classification=classification)


def _init_ai_agent(config: AIConnection, function_params: AIFunctionParameters, logger):
    if config.api_type == 'openai':
        return OpenAIAgent(config, function_params, logger)
    elif config.api_type == 'cohere':
        return CohereAgent(config, function_params, logger)

    raise ValueError(f'Invalid AI API type: {config.api_type}')
