from assemblyline.odm.models.config import AI as AIConfig


class APIException(Exception):
    pass


class EmptyAIResponse(Exception):
    pass


class UnimplementedException(Exception):
    pass


class AIAgent():
    def __init__(self, config: AIConfig, logger) -> None:
        self.config = config
        self.logger = logger

    def continued_ai_conversation(self, messages):
        raise UnimplementedException("Method not implemented yet")

    def detailed_al_submission(self, report, lang="english", with_trace=False):
        raise UnimplementedException("Method not implemented yet")

    def summarized_al_submission(self, report, lang="english", with_trace=False):
        raise UnimplementedException("Method not implemented yet")

    def summarize_code_snippet(self, code, lang="english", with_trace=False):
        raise UnimplementedException("Method not implemented yet")
