from assemblyline.odm.models.config import Config
from assemblyline_ui.helper.ai.cohere import CohereAgent
from assemblyline_ui.helper.ai.openai import OpenAIAgent


def get_ai_agent(config: Config, logger):
    if config.ui.ai.api_type == 'openai':
        return OpenAIAgent(config, logger)
    elif config.ui.ai.api_type == 'cohere':
        return CohereAgent(config, logger)

    raise ValueError(f'Invalid AI API type: {config.api_type}')
