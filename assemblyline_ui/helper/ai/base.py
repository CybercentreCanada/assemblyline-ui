from typing import List
from assemblyline.common import forge
from assemblyline.common.log import PrintLogger
from assemblyline.odm.models.config import AIFunctionParameters, Config, AIConnection
from assemblyline.odm.models.service import Service


class APIException(Exception):
    pass


class EmptyAIResponse(Exception):
    pass


class UnimplementedException(Exception):
    pass


class AIAgent():
    def __init__(self, config: AIConnection, function_params: AIFunctionParameters, logger=None) -> None:
        self.config = config
        self.params = function_params
        self.logger = logger or PrintLogger()
        self.system_prompt = ""
        self.scoring_prompt = ""
        self.classification_prompt = ""
        self.services_prompt = ""
        self.indices_prompt = ""
        self.definition_prompt = ""
        self.extra_context = ""

    def _get_system_message(self, context: str, lang: str):
        return context.replace("$(EXTRA_CONTEXT)", self.extra_context).replace("$(LANG)", lang)

    def continued_ai_conversation(self, messages):
        raise UnimplementedException("Method not implemented yet")

    def detailed_al_submission(self, report, lang="english", with_trace=False):
        raise UnimplementedException("Method not implemented yet")

    def summarized_al_submission(self, report, lang="english", with_trace=False):
        raise UnimplementedException("Method not implemented yet")

    def summarize_code_snippet(self, code, lang="english", with_trace=False):
        raise UnimplementedException("Method not implemented yet")

    def set_system_prompts(self, system_prompt, scoring_prompt, classification_prompt,
                           services_prompt, indices_prompt, definition_prompt):
        self.system_prompt = system_prompt
        self.scoring_prompt = scoring_prompt
        self.classification_prompt = classification_prompt
        self.services_prompt = services_prompt
        self.indices_prompt = indices_prompt
        self.definition_prompt = definition_prompt


class AIAgentPool():
    def __init__(self, config: Config, api_backends: List[AIAgent] = [],
                 logger=None, ds=None, classification=None) -> None:
        # Load pool dependencies
        self.logger = logger or PrintLogger()
        self.config = config
        self.ds = ds or forge.get_datastore()
        self.classification = classification or forge.get_classification()

        if api_backends:
            # Generate system prompts if we have any configured backends
            self.definition_prompt = "## Definitions\n\nThis section will provide " \
                "you with the necessary information to help " \
                "users understand the results produced by Assemblyline. " \
                "Note that these are not Assemblyline results, just definitions."
            self.scoring_prompt = self._build_scoring_prompt()
            self.classification_prompt = self._build_classification_prompt()
            self.services_prompt = self._build_services_prompt()
            self.indices_prompt = self._build_indices_prompt()
            self.system_prompt = self._build_system_prompt()

        # Apply system prompts to backends
        for backend in api_backends:
            backend.set_system_prompts(self.system_prompt, self.scoring_prompt, self.classification_prompt,
                                       self.services_prompt, self.indices_prompt, self.definition_prompt)

        # Load backends
        self.api_backends: List[AIAgent] = api_backends

    def has_backends(self):
        return len(self.api_backends) != 0

    def continued_ai_conversation(self, messages, lang="english"):
        last_error = None
        for backend in self.api_backends:
            try:
                return backend.continued_ai_conversation(messages=messages, lang=lang)
            except APIException as e:
                last_error = e
                pass

        if last_error:
            raise last_error

        raise EmptyAIResponse("Could not find any AI backend to answer the question")

    def detailed_al_submission(self, report, lang="english", with_trace=False):
        last_error = None
        for backend in self.api_backends:
            try:
                return backend.detailed_al_submission(report, lang=lang, with_trace=with_trace)
            except APIException as e:
                last_error = e
                pass

        if last_error:
            raise last_error

        raise EmptyAIResponse("Could not find any AI backend to answer the question")

    def summarized_al_submission(self, report, lang="english", with_trace=False):
        last_error = None
        for backend in self.api_backends:
            try:
                return backend.summarized_al_submission(report, lang=lang, with_trace=with_trace)
            except APIException as e:
                last_error = e
                pass

        if last_error:
            raise last_error

        raise EmptyAIResponse("Could not find any AI backend to answer the question")

    def summarize_code_snippet(self, code, lang="english", with_trace=False):
        last_error = None
        for backend in self.api_backends:
            try:
                return backend.summarize_code_snippet(code, lang=lang, with_trace=with_trace)
            except APIException as e:
                last_error = e
                pass

        if last_error:
            raise last_error

        raise EmptyAIResponse("Could not find any AI backend to answer the question")

    def _build_scoring_prompt(self):
        scoring = f"""Assemblyline uses a scoring mechanism where any scores below
{self.config.submission.verdicts.info} is
considered safe, scores between {self.config.submission.verdicts.info} and
{self.config.submission.verdicts.suspicious} are considered informational,
scores between {self.config.submission.verdicts.suspicious} and
{self.config.submission.verdicts.highly_suspicious} are considered suspicious,
scores between {self.config.submission.verdicts.highly_suspicious} and
{self.config.submission.verdicts.malicious} are considered highly-suspicious and
scores with {self.config.submission.verdicts.malicious} points and up are
considered malicious.""".replace('\n', ' ')
        return f"""### Assemblyline scoring definitions\n\n{scoring}"""

    def _build_classification_prompt(self):
        markings = '\n'.join([f"{marking} = {description}" for marking,
                             description in self.classification.description.items()])
        return f"""### Classification Marking definitions

Assemblyline can classify/restrict access to its output with the following markings:

{markings}"""

    def _build_services_prompt(self):
        service_list: List[Service] = self.ds.list_all_services()

        def safe_description(description):
            return description.replace("</br>", "\n").replace('\n', '\n  ')

        if service_list:
            services = "\n".join(
                [f"name: {srv.name}\ncategory: {srv.category}"
                 f"\ndescription: |\n  {safe_description(srv.description)}"
                 for srv in service_list])
        else:
            services = "No services deployed on this system"
        return f"### Services and plugin definitions\n\nAssemblyline does its processing using only the" \
            f"following services/plugins:\n\n{services}"

    def _build_indices_prompt(self):
        collections = []
        for index in ['alert', 'file', 'result', 'signature', 'submission']:
            collection = self.ds.get_collection(index)
            collection_fields = collection.fields(include_description=True)
            collections.append(
                f"\n#### {index.upper()} index definition\nThis is the list of fields that are available for "
                f"query in the {index} index with their description and data type.\n")
            collections.append(
                "\n".join(
                    [f"{name}: {field['description']} [{field['type']}]" for name,
                     field in collection_fields.items() if field['indexed']]))
        indices = '\n'.join(collections)
        return "### Data index definitions\n\nAssemblyline has multiple indices where it stores the data, theses " \
               f"indices can be queried with the lucene syntax.\n{indices}"

    def _build_system_prompt(self):
        return f"{self.definition_prompt}\n\n" \
            f"{self.scoring_prompt}\n\n{self.classification_prompt}\n\n" \
            f"{self.services_prompt}\n\n{self.indices_prompt}\n\n"


if __name__ == "__main__":
    agent = AIAgentPool(forge.get_config(), main_api=None)
    with open("prompt.txt", 'wb') as myfile:
        myfile.write(agent.system_prompt.encode())
