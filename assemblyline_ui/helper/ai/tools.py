"""
Generic tool registry and executor for AI agentic workflows.

Tools are registered via configuration (values.yaml) and can be:
- 'builtin': Native Assemblyline operations (search, file access, etc.)
- 'external_http': HTTP calls to external APIs

Deployers register tools and agent profiles in their values.yaml. The AI agent
framework converts tool definitions to OpenAI function-calling format and
executes tool calls returned by the LLM.
"""
import json
import logging
from typing import Any, Callable, Dict, List, Optional

import requests
from azure.identity import DefaultAzureCredential

from assemblyline.odm.models.config import AIToolDefinition

logger = logging.getLogger('assemblyline.ui.ai.tools')

# Maximum response size from external tools to prevent context overflow
MAX_TOOL_RESPONSE_SIZE = 64 * 1024  # 64 KB


class ToolExecutionError(Exception):
    """Raised when a tool fails to execute."""
    pass


class ToolRegistry:
    """Registry that maps tool names to their definitions and executors."""

    def __init__(self, tool_definitions: List[AIToolDefinition], ds=None, filestore=None,
                 identify=None, config=None):
        self._tools: Dict[str, AIToolDefinition] = {}
        self._builtin_handlers: Dict[str, Callable] = {}
        self._ds = ds
        self._filestore = filestore
        self._identify = identify
        self._config = config

        # Register built-in tool handlers
        self._register_builtins()

        # Load tool definitions from config
        for tool_def in tool_definitions:
            self._tools[tool_def.name] = tool_def

    def _register_builtins(self):
        """Register handlers for built-in AL-native tools."""
        self._builtin_handlers = {
            'search_index': self._tool_search_index,
            'get_file_info': self._tool_get_file_info,
            'get_file_results': self._tool_get_file_results,
            'get_submission': self._tool_get_submission,
            'get_file_ascii': self._tool_get_file_ascii,
            'get_file_hex': self._tool_get_file_hex,
            'get_service_result': self._tool_get_service_result,
            'list_submissions_for_file': self._tool_list_submissions_for_file,
            'submit_url': self._tool_submit_url,
            'submit_sha256': self._tool_submit_sha256,
            'resubmit_file': self._tool_resubmit_file,
            'get_submission_status': self._tool_get_submission_status,
        }

    def get_tool_names(self) -> List[str]:
        """Return all registered tool names."""
        return list(self._tools.keys())

    def get_tools_for_agent(self, agent_tool_names: List[str]) -> List[AIToolDefinition]:
        """Return tool definitions for a specific agent's tool list."""
        return [self._tools[name] for name in agent_tool_names if name in self._tools]

    def to_openai_tools(self, tool_names: List[str]) -> List[Dict]:
        """Convert tool definitions to OpenAI function-calling format."""
        openai_tools = []
        for name in tool_names:
            tool_def = self._tools.get(name)
            if not tool_def:
                continue

            # Build JSON Schema properties from parameter definitions
            properties = {}
            required = []
            for param in tool_def.parameters:
                prop: Dict[str, Any] = {
                    'type': param.type,
                    'description': param.description,
                }
                if param.enum:
                    prop['enum'] = param.enum
                properties[param.name] = prop
                if param.required:
                    required.append(param.name)

            openai_tools.append({
                'type': 'function',
                'function': {
                    'name': tool_def.name,
                    'description': tool_def.description,
                    'parameters': {
                        'type': 'object',
                        'properties': properties,
                        'required': required,
                    }
                }
            })
        return openai_tools

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any], user: Dict = None) -> str:
        """Execute a tool by name with the given arguments. Returns a string result."""
        tool_def = self._tools.get(tool_name)
        if not tool_def:
            return json.dumps({'error': f'Unknown tool: {tool_name}'})

        try:
            if tool_def.tool_type == 'builtin':
                return self._execute_builtin(tool_name, arguments, user)
            elif tool_def.tool_type == 'external_http':
                return self._execute_external_http(tool_def, arguments)
            else:
                return json.dumps({'error': f'Unknown tool type: {tool_def.tool_type}'})
        except ToolExecutionError as e:
            return json.dumps({'error': str(e)})
        except Exception as e:
            logger.exception(f"Tool execution failed: {tool_name}")
            return json.dumps({'error': f'Tool execution failed: {type(e).__name__}: {e}'})

    def _execute_builtin(self, tool_name: str, arguments: Dict[str, Any], user: Dict = None) -> str:
        """Execute a built-in AL-native tool."""
        handler = self._builtin_handlers.get(tool_name)
        if not handler:
            return json.dumps({'error': f'No handler for builtin tool: {tool_name}'})
        result = handler(arguments, user)
        return self._truncate_result(json.dumps(result, default=str))

    def _execute_external_http(self, tool_def: AIToolDefinition, arguments: Dict[str, Any]) -> str:
        """Execute an external HTTP tool call."""
        url = tool_def.endpoint_url
        if not url:
            return json.dumps({'error': 'No endpoint_url configured for external tool'})

        # Substitute {param} placeholders in the URL
        for key, value in arguments.items():
            url = url.replace(f'{{{key}}}', str(value))

        headers = dict(tool_def.endpoint_headers) if tool_def.endpoint_headers else {}
        headers.setdefault('Content-Type', 'application/json')

        # Handle Federated Identity Credentials auth
        if tool_def.use_fic:
            try:
                credentials = DefaultAzureCredential()
                token = credentials.get_token('https://cognitiveservices.azure.com/.default').token
                headers['Authorization'] = f'Bearer {token}'
            except Exception as e:
                logger.warning(f"FIC auth failed for tool {tool_def.name}: {e}")
                return json.dumps({'error': f'Authentication failed: {e}'})

        try:
            if tool_def.http_method == 'GET':
                resp = requests.get(url, headers=headers, params=arguments, timeout=tool_def.timeout)
            elif tool_def.http_method == 'POST':
                resp = requests.post(url, headers=headers, json=arguments, timeout=tool_def.timeout)
            elif tool_def.http_method == 'PUT':
                resp = requests.put(url, headers=headers, json=arguments, timeout=tool_def.timeout)
            else:
                return json.dumps({'error': f'Unsupported HTTP method: {tool_def.http_method}'})

            if not resp.ok:
                return json.dumps({'error': f'HTTP {resp.status_code}: {resp.text[:500]}'})

            return self._truncate_result(resp.text)

        except requests.Timeout:
            return json.dumps({'error': f'Tool call timed out after {tool_def.timeout}s'})
        except requests.RequestException as e:
            return json.dumps({'error': f'HTTP request failed: {e}'})

    def _truncate_result(self, result: str) -> str:
        """Truncate tool results to prevent LLM context overflow."""
        if len(result) > MAX_TOOL_RESPONSE_SIZE:
            return result[:MAX_TOOL_RESPONSE_SIZE] + '\n... [truncated]'
        return result

    # ── Built-in tool handlers ──────────────────────────────────────────

    def _tool_search_index(self, args: Dict, user: Optional[Dict]) -> Any:
        """Search an Assemblyline datastore index with a Lucene query."""
        if not self._ds:
            raise ToolExecutionError("Datastore not available")

        index = args.get('index', 'submission')
        query = args.get('query', '*')
        rows = min(int(args.get('rows', 10)), 100)
        fl = args.get('fl', '')

        allowed_indices = ['alert', 'file', 'result', 'signature', 'submission']
        if index not in allowed_indices:
            raise ToolExecutionError(f"Index must be one of: {allowed_indices}")

        collection = self._ds.get_collection(index)
        result = collection.search(query, rows=rows, fl=fl if fl else None, as_obj=False)
        return {
            'total': result['total'],
            'items': result['items'][:rows],
        }

    def _tool_get_file_info(self, args: Dict, user: Optional[Dict]) -> Any:
        """Get file metadata by SHA256."""
        if not self._ds:
            raise ToolExecutionError("Datastore not available")
        sha256 = args.get('sha256', '')
        file_obj = self._ds.file.get(sha256, as_obj=False)
        if not file_obj:
            raise ToolExecutionError(f"File not found: {sha256}")
        return file_obj

    def _tool_get_file_results(self, args: Dict, user: Optional[Dict]) -> Any:
        """Get all service results for a file."""
        if not self._ds:
            raise ToolExecutionError("Datastore not available")
        sha256 = args.get('sha256', '')
        results = self._ds.result.search(f'id:{sha256}*', rows=100, as_obj=False)
        return {
            'total': results['total'],
            'items': results['items'],
        }

    def _tool_get_submission(self, args: Dict, user: Optional[Dict]) -> Any:
        """Get submission details by SID."""
        if not self._ds:
            raise ToolExecutionError("Datastore not available")
        sid = args.get('sid', '')
        submission = self._ds.submission.get(sid, as_obj=False)
        if not submission:
            raise ToolExecutionError(f"Submission not found: {sid}")
        return submission

    def _tool_get_file_ascii(self, args: Dict, user: Optional[Dict]) -> Any:
        """Get ASCII representation of a file (first N bytes)."""
        if not self._filestore:
            raise ToolExecutionError("Filestore not available")
        sha256 = args.get('sha256', '')
        max_bytes = min(int(args.get('max_bytes', 4096)), 65536)
        data = self._filestore.get(sha256)
        if not data:
            raise ToolExecutionError(f"File not found in filestore: {sha256}")
        data = data[:max_bytes]
        return {
            'sha256': sha256,
            'size': len(data),
            'content': data.decode('ascii', errors='replace'),
        }

    def _tool_get_file_hex(self, args: Dict, user: Optional[Dict]) -> Any:
        """Get hex dump of a file region."""
        if not self._filestore:
            raise ToolExecutionError("Filestore not available")
        sha256 = args.get('sha256', '')
        offset = int(args.get('offset', 0))
        length = min(int(args.get('length', 512)), 4096)
        data = self._filestore.get(sha256)
        if not data:
            raise ToolExecutionError(f"File not found in filestore: {sha256}")
        region = data[offset:offset + length]
        hex_lines = []
        for i in range(0, len(region), 16):
            chunk = region[i:i + 16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            hex_lines.append(f'{offset + i:08x}  {hex_part:<48s}  {ascii_part}')
        return {
            'sha256': sha256,
            'offset': offset,
            'length': len(region),
            'hex_dump': '\n'.join(hex_lines),
        }

    def _tool_get_service_result(self, args: Dict, user: Optional[Dict]) -> Any:
        """Get a specific service result by result key."""
        if not self._ds:
            raise ToolExecutionError("Datastore not available")
        result_key = args.get('result_key', '')
        result = self._ds.result.get(result_key, as_obj=False)
        if not result:
            raise ToolExecutionError(f"Result not found: {result_key}")
        return result

    def _tool_list_submissions_for_file(self, args: Dict, user: Optional[Dict]) -> Any:
        """List submissions containing a specific file."""
        if not self._ds:
            raise ToolExecutionError("Datastore not available")
        sha256 = args.get('sha256', '')
        rows = min(int(args.get('rows', 10)), 50)
        results = self._ds.submission.search(f'files.sha256:{sha256}', rows=rows, fl='sid,times,state', as_obj=False)
        return {
            'total': results['total'],
            'items': results['items'],
        }

    # ── Submission tools ────────────────────────────────────────────────

    def _get_submission_client(self):
        """Lazy-import and create a SubmissionClient to avoid circular imports."""
        if not all([self._ds, self._filestore, self._identify, self._config]):
            raise ToolExecutionError("Submission tools require datastore, filestore, identify, and config")
        from assemblyline_core.submission_client import SubmissionClient
        return SubmissionClient(datastore=self._ds, filestore=self._filestore,
                                config=self._config, identify=self._identify)

    def _build_submission_params(self, user: Optional[Dict], args: Dict) -> Dict:
        """Build submission params from user defaults and tool arguments."""
        if not user:
            raise ToolExecutionError("Submission tools require an authenticated user")

        params = {
            'submitter': user.get('uname', 'agent'),
            'groups': user.get('groups', ['USERS']),
            'classification': user.get('classification', 'TLP:CLEAR'),
            'description': args.get('description', 'Submitted by AI agent'),
            'max_extracted': self._config.submission.default_max_extracted if self._config else 500,
            'max_supplementary': self._config.submission.default_max_supplementary if self._config else 500,
        }

        # Allow agent to select specific services
        services = args.get('services')
        if services:
            if isinstance(services, str):
                services = [s.strip() for s in services.split(',')]
            params['services'] = {'selected': services, 'excluded': [], 'resubmit': []}

        return params

    def _tool_submit_url(self, args: Dict, user: Optional[Dict]) -> Any:
        """Submit a URL for analysis. Returns the submission ID."""
        import hashlib
        import os
        import tempfile
        from assemblyline.odm.messages.submission import Submission
        from assemblyline_core.submission_client import SubmissionException
        from assemblyline_ui.helper.submission import download_from_url

        url = args.get('url', '')
        if not url:
            raise ToolExecutionError("URL is required")

        client = self._get_submission_client()
        params = self._build_submission_params(user, args)
        params['description'] = args.get('description', f'AI agent URL submission: {url}')

        try:
            # Download the URL to a temp file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.download') as f:
                temp_path = f.name

            download_from_url(url, temp_path)

            with open(temp_path, 'rb') as f:
                sha256 = hashlib.sha256(f.read()).hexdigest()

            name = args.get('name') or url.split('/')[-1].split('?')[0] or 'download'

            submission_obj = Submission({
                "files": [],
                "metadata": {'submitted_by': 'ai_agent'},
                "params": params,
            })

            result = client.submit(submission_obj, local_files=[(name, temp_path)])
            return {
                'sid': str(result.sid),
                'sha256': sha256,
                'status': 'submitted',
                'message': f'URL submitted. Use get_submission_status with sid={result.sid} to check progress.',
            }

        except SubmissionException as e:
            raise ToolExecutionError(f"Submission failed: {e}")
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def _tool_submit_sha256(self, args: Dict, user: Optional[Dict]) -> Any:
        """Submit an existing file (by SHA256) for reanalysis, optionally with specific services."""
        from assemblyline.odm.messages.submission import Submission
        from assemblyline_core.submission_client import SubmissionException

        sha256 = args.get('sha256', '')
        if not sha256:
            raise ToolExecutionError("SHA256 is required")

        if not self._filestore.exists(sha256):
            raise ToolExecutionError(f"File not found in filestore: {sha256}")

        client = self._get_submission_client()
        params = self._build_submission_params(user, args)
        params['description'] = args.get('description', f'AI agent resubmission: {sha256}')

        if args.get('ignore_cache', False):
            params['ignore_cache'] = True

        try:
            submission_obj = Submission({
                "files": [{'sha256': sha256, 'name': args.get('name', sha256)}],
                "metadata": {'submitted_by': 'ai_agent'},
                "params": params,
            })
            result = client.submit(submission_obj)
            return {
                'sid': str(result.sid),
                'sha256': sha256,
                'status': 'submitted',
                'message': f'File submitted. Use get_submission_status with sid={result.sid} to check progress.',
            }
        except SubmissionException as e:
            raise ToolExecutionError(f"Submission failed: {e}")

    def _tool_resubmit_file(self, args: Dict, user: Optional[Dict]) -> Any:
        """Resubmit a file from a previous submission, optionally targeting specific services."""
        from assemblyline.odm.messages.submission import Submission
        from assemblyline_core.submission_client import SubmissionException

        sid = args.get('sid', '')
        if not sid:
            raise ToolExecutionError("Original submission SID is required")

        original = self._ds.submission.get(sid, as_obj=False)
        if not original:
            raise ToolExecutionError(f"Original submission not found: {sid}")

        client = self._get_submission_client()
        params = self._build_submission_params(user, args)
        params['description'] = args.get('description', f'AI agent resubmission of {sid}')
        params['ignore_cache'] = True

        try:
            submission_obj = Submission({
                "files": original.get('files', []),
                "metadata": {**original.get('metadata', {}), 'submitted_by': 'ai_agent', 'resubmit_from': sid},
                "params": params,
            })
            result = client.submit(submission_obj)
            return {
                'sid': str(result.sid),
                'original_sid': sid,
                'status': 'submitted',
                'message': f'Resubmitted. Use get_submission_status with sid={result.sid} to check progress.',
            }
        except SubmissionException as e:
            raise ToolExecutionError(f"Resubmission failed: {e}")

    def _tool_get_submission_status(self, args: Dict, user: Optional[Dict]) -> Any:
        """Check the status of a submission and return results if complete."""
        if not self._ds:
            raise ToolExecutionError("Datastore not available")

        sid = args.get('sid', '')
        if not sid:
            raise ToolExecutionError("SID is required")

        submission = self._ds.submission.get(sid, as_obj=False)
        if not submission:
            raise ToolExecutionError(f"Submission not found: {sid}")

        state = submission.get('state', 'unknown')
        response = {
            'sid': sid,
            'state': state,
            'files': submission.get('files', []),
            'max_score': submission.get('max_score', 0),
            'times': submission.get('times', {}),
        }

        if state == 'completed':
            response['verdict'] = submission.get('verdict', {})
            response['error_count'] = len(submission.get('errors', []))
            response['result_count'] = len(submission.get('results', []))

            file_results = []
            for f in submission.get('files', []):
                sha256 = f.get('sha256', '')
                results = self._ds.result.search(f'id:{sha256}*', rows=100,
                                                  fl='result.score,response.service_name', as_obj=False)
                services = []
                for r in results.get('items', []):
                    svc = r.get('response', {}).get('service_name', 'unknown')
                    score = r.get('result', {}).get('score', 0)
                    services.append({'service': svc, 'score': score})
                file_results.append({'sha256': sha256, 'services': services})
            response['file_results'] = file_results

        return response
