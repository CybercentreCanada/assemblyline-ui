from typing import List
from assemblyline.common import forge
from assemblyline.common.log import PrintLogger
from assemblyline.odm.models.config import Config
from assemblyline.odm.models.service import Service


class APIException(Exception):
    pass


class EmptyAIResponse(Exception):
    pass


class UnimplementedException(Exception):
    pass


class AIAgent():
    def __init__(self, config: Config, logger=None) -> None:
        self.config = config.ui.ai
        self.logger = logger or PrintLogger()
        self.system_config = config
        self.classification = forge.get_classification()
        self.scoring_prompt = self._build_scoring_prompt()
        self.classification_prompt = self._build_classification_prompt()
        self.services_prompt = self._build_services_prompt()
        self.indices_prompt = self._build_indices_prompt()

    def continued_ai_conversation(self, messages):
        raise UnimplementedException("Method not implemented yet")

    def detailed_al_submission(self, report, lang="english", with_trace=False):
        raise UnimplementedException("Method not implemented yet")

    def summarized_al_submission(self, report, lang="english", with_trace=False):
        raise UnimplementedException("Method not implemented yet")

    def summarize_code_snippet(self, code, lang="english", with_trace=False):
        raise UnimplementedException("Method not implemented yet")

    def _build_scoring_prompt(self):
        scoring = f"""Assemblyline uses a scoring mechanism where any scores below
{self.system_config.submission.verdicts.info} is
considered safe, scores between {self.system_config.submission.verdicts.info} and
{self.system_config.submission.verdicts.suspicious} are considered informational,
scores between {self.system_config.submission.verdicts.suspicious} and
{self.system_config.submission.verdicts.highly_suspicious} are considered suspicious,
scores between {self.system_config.submission.verdicts.highly_suspicious} and
{self.system_config.submission.verdicts.malicious} are considered highly-suspicious and
scores with {self.system_config.submission.verdicts.malicious} points and up are
considered malicious.""".replace('\n', ' ')
        return f"""### Assemblyline scoring definitions\n\n{scoring}"""

    def _build_classification_prompt(self):
        markings = '\n'.join([f"{marking} = {description}" for marking,
                             description in self.classification.description.items()])
        return f"""### Classification Marking definitions

Assemblyline can classify/restrict access to its output with the following markings:

{markings}"""

    def _build_services_prompt(self):
        ds = forge.get_datastore()
        service_list: List[Service] = ds.list_all_services()

        def safe_description(description):
            return description.replace('\n', '\n     ')

        services = "\n".join(
            [f" - name: {srv.name}\n   category: {srv.category}"
             f"\n   description: |\n     {safe_description(srv.description)}"
             for srv in service_list])
        return f"### Services and plugin definitions\n\nAssemblyline does its processing using only the" \
            f"following services/plugins:\n\n{services}"

    def _build_indices_prompt(self):
        return ""


if __name__ == "__main__":
    agent = AIAgent(forge.get_config())
    print(agent.scoring_prompt)
    print(agent.classification_prompt)
    print(agent.services_prompt)
    print(agent.indices_prompt)
