from assemblyline.odm.models.config import AI as AIConfig
from assemblyline_ui.helper.ai.cohere import CohereAgent
from assemblyline_ui.helper.ai.openai import OpenAIAgent


def get_ai_agent(config: AIConfig, logger):
    if config.api_type == 'openai':
        return OpenAIAgent(config, logger)
    elif config.api_type == 'cohere':
        return CohereAgent(config, logger)

    raise ValueError(f'Invalid AI API type: {config.api_type}')
