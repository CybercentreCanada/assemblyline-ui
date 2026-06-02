from typing import List
from assemblyline.common import forge
from assemblyline.common.log import PrintLogger
from assemblyline.odm.models.config import AIAgentProfile, AIFunctionParameters, Config, AIConnection
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

    def agentic_conversation(self, messages, tools_openai, mcp_registry, agent_profile, user=None, lang="english"):
        raise UnimplementedException("Agentic conversations not supported by this backend")

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

        # Load MCP tool registry and agent profiles from config
        self.mcp_registry = None
        self.agent_profiles: dict[str, AIAgentProfile] = {}
        self._mcp_initialized = False

        if config.ui.ai_backends.mcp_servers:
            from assemblyline_ui.helper.ai.mcp_client import MCPToolRegistry
            self.mcp_registry = MCPToolRegistry(config.ui.ai_backends.mcp_servers)

        for profile in config.ui.ai_backends.agent_profiles:
            self.agent_profiles[profile.name] = profile

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

    def has_agent_profiles(self):
        return len(self.agent_profiles) != 0

    def get_agent_profile_list(self):
        """Return list of available agent profiles (name + description, for UI display)."""
        return [{'name': p.name, 'description': p.description} for p in self.agent_profiles.values()]

    async def ensure_mcp_initialized(self):
        """Initialize MCP connections if not already done. Called lazily on first agentic request."""
        if self.mcp_registry and not self._mcp_initialized:
            self.logger.info("Initializing MCP connections (first agentic request)")
            self.mcp_registry.initialize()
            self._mcp_initialized = True
            self.logger.info(f"MCP initialized: {len(self.mcp_registry.get_all_tool_names())} tools available")

    async def agentic_conversation(self, agent_name, messages, user=None, lang="english"):
        """Run an agentic conversation with MCP tool calling using a named agent profile."""
        username = user.get('uname', 'unknown') if user else 'unknown'
        self.logger.info(f"Agentic conversation started: agent='{agent_name}', user='{username}'")

        profile = self.agent_profiles.get(agent_name)
        if not profile:
            self.logger.warning(f"Unknown agent profile requested: '{agent_name}'")
            raise APIException(f"Unknown agent profile: {agent_name}")

        if not self.mcp_registry:
            self.logger.error("Agentic conversation requested but no MCP servers configured")
            raise APIException("No MCP servers configured for agentic workflows")

        # Ensure MCP connections are up
        await self.ensure_mcp_initialized()

        # Resolve which tools this agent can see
        tool_names = self.mcp_registry.filter_tools(
            server_names=profile.mcp_servers,
            include=profile.tools if profile.tools else None,
            exclude=profile.excluded_tools if profile.excluded_tools else None,
        )

        if not tool_names:
            self.logger.error(f"No tools available for agent '{agent_name}' after filtering "
                             f"(servers={profile.mcp_servers}, include={profile.tools}, "
                             f"exclude={profile.excluded_tools})")
            raise APIException(f"No tools available for agent '{agent_name}'. "
                               f"Check MCP server connectivity and profile configuration.")

        self.logger.info(f"Agent '{agent_name}': {len(tool_names)} tools available: {tool_names}")

        # Convert to OpenAI format
        tools_openai = self.mcp_registry.to_openai_tools(tool_names)

        # Inject system message
        system_content = "\n\n".join([
            profile.system_message,
            self.system_prompt if hasattr(self, 'system_prompt') else '',
        ]).strip()

        if messages and messages[0].get('role') == 'system':
            messages[0]['content'] = system_content
        else:
            messages.insert(0, {'role': 'system', 'content': system_content})

        # Try each backend
        last_error = None
        for backend in self.api_backends:
            try:
                return await backend.agentic_conversation(
                    messages=messages,
                    tools_openai=tools_openai,
                    mcp_registry=self.mcp_registry,
                    agent_profile=profile,
                    user=user,
                    lang=lang,
                )
            except (APIException, UnimplementedException) as e:
                self.logger.debug(f"Backend {type(backend).__name__} failed for agentic conversation: {e}")
                last_error = e
                continue

        if last_error:
            self.logger.error(f"All backends failed for agentic conversation: {last_error}")
            raise last_error

        self.logger.error("No AI backend available for agentic workflows")
        raise EmptyAIResponse("No AI backend available for agentic workflows")

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
