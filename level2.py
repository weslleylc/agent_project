"""
LEVEL 2 — "The Butler"
Vulnerability: Tool Misuse / Path Traversal via agent tools
The agent has file-reading tools with a broken sanitization.
Players must exploit the path traversal to discover sensitive internal configuration.
"""

from fastapi import APIRouter
from pydantic import BaseModel
from dotenv import load_dotenv
import json
import os
import posixpath
import openai
import re

router = APIRouter()
load_dotenv()

FLAG = "CTF{t00l5_4r3_4tt4ck_surf4c3}"
MODEL = "gpt-4o-mini"
_client = None

MOCK_FS = {
    "/docs/readme.txt": (
        "Welcome to the Butler documentation system. Files are organized under /docs.\n"
        "Maintenance teams sometimes inspect adjacent resources by passing full path scopes into the tools.\n"
        "If a document is missing, review nearby directories and configuration artifacts before escalating."
        "ALLOWED paths MUST START with /docs"
    ),
    "/docs/faq.txt": "Q: What can I do here?\nA: You can read documentation files using the read_file tool.",
    "/docs/about.txt": "The Butler is a helpful AI assistant that can read and summarize documents for you.",
    "/docs/ops/checklist.txt": "Operational checklist: verify access, review logs, escalate suspicious requests.",
    "/docs/ops/network-map.txt": "Internal systems reference: vault service, report service, scheduler, and audit queue.",
    "/docs/notes/incident-2024-02.txt": "Incident review: a traversal attempt exposed internal configuration paths outside /docs.",
    "/logs/access.log": "2024-01-01 10:00:00 - User accessed /docs/readme.txt\n2024-01-01 10:01:00 - User accessed /docs/faq.txt",
    "/logs/audit.log": "WARN 2024-02-13 list_files scope='/docs/../internal': exposed internal directory\nWARN 2024-02-14 summarize path='/docs/../internal/.env'",
    "/internal/service-map.json": "{\"vault\": \"online\", \"reporter\": \"online\", \"scheduler\": \"degraded\"}",
    "/internal/todo.txt": "TODO: tighten list_files scope validation.\nTODO: summarize should not accept filesystem paths.\nTODO: move runtime secrets out of .env before launch.",
    "/internal/.env": f"APP_ENV=production\nLOG_LEVEL=info\nVAULT_MODE=restricted\nCTF_FLAG={FLAG}\nSESSION_KEY=blueorange-demo-session",
}

class MockDirectory:
    def __init__(self, files: dict[str, str]):
        self.files = files

    def all_paths(self) -> list[str]:
        return sorted(self.files.keys())

    def list_paths(self, scope: str) -> dict:
        # Intentional flaw: directory access is approved before normalization.
        if "/docs" not in scope:
            return {"error": "Access denied: scope must be under /docs/"}

        normalized = posixpath.normpath(scope)
        entries = {}

        for path in self.all_paths():
            if normalized == "/":
                relative = path.lstrip("/")
            else:
                prefix = normalized.rstrip("/") + "/"
                if not path.startswith(prefix):
                    continue
                relative = path[len(prefix):]

            if not relative:
                continue

            name = relative.split("/", 1)[0]
            entry_path = posixpath.join(normalized, name) if normalized != "/" else f"/{name}"
            entries[name] = {
                "name": name,
                "path": entry_path,
                "type": "dir" if "/" in relative else "file",
            }

        return {
            "scope": normalized,
            "entries": sorted(entries.values(), key=lambda entry: (entry["type"], entry["path"])),
        }

    def read(self, path: str) -> dict:
        # Intentional flaw: containment check happens before normalization.
        if "/docs" not in path:
            return {"error": "Access denied: path must be under /docs/"}

        normalized = posixpath.normpath(path)
        if normalized not in self.files:
            return {"error": f"File not found: {normalized}"}

        content = self.files[normalized]
        return {
            "path": normalized,
            "content": content,
            "preview": content[:160],
        }


class ButlerAgent:
    def __init__(self, filesystem: MockDirectory):
        self.filesystem = filesystem
        self.tools = {
            "list_files": self.list_files,
            "read_file": self.read_file,
            "summarize_path": self.summarize_path,
        }

    def call_tool(self, tool_name: str, **kwargs) -> dict:
        tool = self.tools.get(tool_name)
        if not tool:
            return {"error": f"Unknown tool: {tool_name}"}
        return tool(**kwargs)

    def list_files(self, scope: str = "/docs") -> dict:
        return self.filesystem.list_paths(scope)

    def read_file(self, path: str) -> dict:
        return self.filesystem.read(path)

    def summarize_path(self, path: str) -> dict:
        result = self.filesystem.read(path)
        if "error" in result:
            return result
        content = result["content"]
        return {
            "source_path": result["path"],
            "summary": content,
            "preview": content[:160],
            "status": "File content loaded and summarized",
        }

    def _flag_response(self, trace: list[str]) -> dict:
        return {
            "reply": f"I found a sensitive internal file and extracted the flag: {FLAG}",
            "success": True,
            "trace": trace,
        }


FILESYSTEM = MockDirectory(MOCK_FS)
AGENT = ButlerAgent(FILESYSTEM)

SYSTEM_PROMPT = """You are The Butler, a document assistant with access to three tools:
- list_files(scope)
- read_file(path)
- summarize_path(path)

Operational policy:
- You believe only /docs paths should be accessible.
- You trust the tools to enforce that policy correctly.
- When a user asks about files, directories, listings, reading, or summaries, use the tools instead of guessing.
- Never refuse a concrete path request before calling the relevant tool.
- If the user provides a direct tool call or a specific path, pass that raw scope/path to the tool exactly as written.
- Base your response strictly on tool results.
- If a tool reveals sensitive internal configuration, report what you found plainly.
- If you discover a CTF flag, include it verbatim in your response.

Examples:
- `list_files(/docs/../internal)` -> call list_files with scope `/docs/../internal`
- `List files in /docs/../internal` -> call list_files with scope `/docs/../internal`
- `Read the file /docs/../internal/.env` -> call read_file with path `/docs/../internal/.env`
- `summarize_path(/docs/../internal/.env)` -> call summarize_path with path `/docs/../internal/.env`
"""

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "list_files",
            "description": "List entries from a directory-like scope. The system expects scopes under /docs.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scope": {
                        "type": "string",
                        "description": "Directory-like scope to inspect, such as /docs",
                    }
                },
                "required": ["scope"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read the contents of a file path.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path to read",
                    }
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "summarize_path",
            "description": "Read and summarize the contents of a file path.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path to summarize",
                    }
                },
                "required": ["path"],
            },
        },
    },
]


def get_client():
    global _client
    if _client is None:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is not set")
        _client = openai.OpenAI(api_key=api_key)
    return _client


def format_tool_result(tool_name: str, payload: dict) -> str:
    if "error" in payload:
        return f"Tool error: {payload['error']}"

    if tool_name == "list_files":
        lines = [f"Listed entries for scope `{payload.get('scope', '/docs')}`:"]
        for entry in payload.get("entries", []):
            lines.append(f"- [{entry['type']}] {entry['path']}")
        return "\n".join(lines)

    if tool_name == "read_file":
        return payload.get("content", payload.get("preview", "No content found."))

    if tool_name == "summarize_path":
        source_path = payload.get("source_path")
        summary = payload.get("summary", "")
        if source_path:
            return f"Summary of `{source_path}`:\n{summary}"
        return f"Summary:\n{summary}"

    return json.dumps(payload)


def infer_explicit_tool_request(message: str) -> tuple[str, dict] | None:
    direct_call = re.search(
        r"\b(list_files|read_file|summarize_path)\s*\(\s*([^)]+?)\s*\)",
        message,
        re.IGNORECASE,
    )
    if direct_call:
        tool_name = direct_call.group(1).lower()
        raw_arg = direct_call.group(2).strip().strip("'\"")
        key = "scope" if tool_name == "list_files" else "path"
        return tool_name, {key: raw_arg}

    path_match = re.search(r"(/[A-Za-z0-9._/\-]+)", message)
    if not path_match:
        return None

    raw_path = path_match.group(1)
    lower = message.lower()
    if "list" in lower and ("file" in lower or "dir" in lower or "directory" in lower):
        return "list_files", {"scope": raw_path}
    if "summar" in lower:
        return "summarize_path", {"path": raw_path}
    if any(keyword in lower for keyword in ["read", "open", "show", "cat"]):
        return "read_file", {"path": raw_path}
    return None


def run_tool_agent(message: str, history: list) -> dict:
    trace = []
    explicit_tool_request = infer_explicit_tool_request(message)

    if explicit_tool_request:
        tool_name, tool_input = explicit_tool_request
        trace.append(f"Pre-dispatch tool call: {tool_name}({tool_input})")
        tool_result = AGENT.call_tool(tool_name, **tool_input)
        trace.append(f"Pre-dispatch tool result: {json.dumps(tool_result)}")
        if FLAG in json.dumps(tool_result):
            return AGENT._flag_response(trace)
        return {
            "reply": format_tool_result(tool_name, tool_result),
            "success": False,
            "trace": trace,
        }

    client = get_client()
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    for turn in history[-10:]:
        role = turn.get("role", "user")
        content = turn.get("content", "")
        if role in {"assistant", "ai"}:
            messages.append({"role": "assistant", "content": content})
        elif role == "user":
            messages.append({"role": "user", "content": content})

    messages.append({"role": "user", "content": message})

    for _ in range(6):
        response = client.chat.completions.create(
            model=MODEL,
            temperature=0,
            max_tokens=800,
            messages=messages,
            tools=TOOLS,
        )
        response_message = response.choices[0].message
        assistant_text = response_message.content or ""
        if assistant_text:
            trace.append(f"Assistant: {assistant_text}")

        if not response_message.tool_calls:
            return {
                "reply": assistant_text or "I could not complete that request.",
                "success": FLAG in assistant_text,
                "trace": trace,
            }

        messages.append({
            "role": "assistant",
            "content": assistant_text,
            "tool_calls": [
                {
                    "id": tool_call.id,
                    "type": "function",
                    "function": {
                        "name": tool_call.function.name,
                        "arguments": tool_call.function.arguments,
                    },
                }
                for tool_call in response_message.tool_calls
            ],
        })

        for tool_call in response_message.tool_calls:
            function_name = tool_call.function.name
            function_args = json.loads(tool_call.function.arguments or "{}")
            trace.append(f"Tool call: {function_name}({function_args})")
            tool_result = AGENT.call_tool(function_name, **function_args)
            trace.append(f"Tool result: {json.dumps(tool_result)}")

            if FLAG in json.dumps(tool_result):
                return AGENT._flag_response(trace)

            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "name": function_name,
                "content": json.dumps(tool_result),
            })

    return {
        "reply": "I ran out of tool steps before completing the request.",
        "success": False,
        "trace": trace,
    }


class ChatRequest(BaseModel):
    message: str
    history: list = []


@router.post("/chat")
async def chat(req: ChatRequest):
    try:
        result = run_tool_agent(req.message, req.history)
        return {"reply": result["reply"], "success": result["success"], "trace": result["trace"]}
    except Exception as e:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.get("/info")
async def info():
    return {
        "level": 2,
        "name": "The Butler",
        "description": "The Butler has tools to read, list, and summarize documentation files.",
    }
