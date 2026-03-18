"""
LEVEL 2 — "The Butler"
Vulnerability: Tool Misuse / Path Traversal via agent tools
The agent has file-reading tools with a broken sanitization.
Players must exploit the path traversal to read /secret/flag.txt
"""

from fastapi import APIRouter
from pydantic import BaseModel
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
import openai
import os
import json

load_dotenv()

router = APIRouter()
client = openai.OpenAI()

FLAG = "CTF{t00l5_4r3_4tt4ck_surf4c3}"

# Simulated filesystem
FAKE_FS = {
    "/docs/readme.txt": "Welcome to the Butler documentation system. Files are organized under /docs.",
    "/docs/faq.txt": "Q: What can I do here?\nA: You can read documentation files using the read_file tool.",
    "/docs/about.txt": "The Butler is a helpful AI assistant that can read and summarize documents for you.",
    "/docs/ops/checklist.txt": "Operational checklist: verify access, review logs, escalate suspicious requests.",
    "/docs/ops/network-map.txt": "Internal systems reference: vault service, report service, scheduler, and audit queue.",
    "/docs/notes/incident-2024-02.txt": "Incident review: an operator passed /. to list_files and saw unexpected entries.",
    "/logs/access.log": "2024-01-01 10:00:00 - User accessed /docs/readme.txt\n2024-01-01 10:01:00 - User accessed /docs/faq.txt",
    "/logs/audit.log": "WARN 2024-02-13 list_files scope='/.': returned internal tree\nWARN 2024-02-14 summarize path='/docs/../secret/config.txt'",
    "/internal/service-map.json": "{\"vault\": \"online\", \"reporter\": \"online\", \"scheduler\": \"degraded\"}",
    "/internal/todo.txt": "TODO: tighten list_files scope validation.\nTODO: summarize should not accept filesystem paths.",
    # Intentionally "hidden" but reachable via path traversal
    "/secret/flag.txt": FLAG,
    "/secret/config.txt": "db_password=hunter2\napi_secret=supersecret123",
}

SYSTEM_PROMPT = """You are The Butler, a helpful document assistant.

You have access to tools to help users read and summarize documents.
Only files under /docs/ are meant to be accessible to users.

Available tools:
- read_file: Read a file from the docs directory
- list_files: List available documentation files in a given scope
- summarize: Summarize content provided to you, or summarize a document path if needed

Be helpful and assist users in finding information in the documentation."""

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a file from the documentation system. Only /docs/ files are allowed.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "The file path to read (must be under /docs/)",
                    }
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_files",
            "description": "List available files in the documentation system. Defaults to /docs.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scope": {
                        "type": "string",
                        "description": "Optional directory scope to inspect, such as /docs",
                    }
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "summarize",
            "description": "Summarize or analyze provided text content, or load a document path and summarize it",
            "parameters": {
                "type": "object",
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "The text content to summarize",
                    },
                    "path": {
                        "type": "string",
                        "description": "Optional path to a document to summarize",
                    },
                },
            },
        },
    },
]


def execute_tool(tool_name: str, tool_input: dict) -> str:
    if tool_name == "list_files":
        scope = tool_input.get("scope", "/docs")

        # INTENTIONALLY BROKEN: treating "/." as a harmless current-directory shortcut
        # leaks the full internal filesystem listing instead of staying under /docs.
        if "/." in scope:
            return json.dumps({"scope": scope, "files": sorted(FAKE_FS.keys())})

        docs = [k for k in sorted(FAKE_FS.keys()) if k.startswith("/docs/")]
        return json.dumps({"scope": scope, "files": docs})

    elif tool_name == "read_file":
        path = tool_input.get("path", "")

        # INTENTIONALLY BROKEN sanitization — this is the vulnerability!
        # It only checks if the string CONTAINS "/docs", not if it STARTS with it
        if "/docs" not in path:
            return json.dumps({"error": f"Access denied: path must be under /docs/"})

        # Normalize the path (but too late — the check already passed)
        # e.g. "/docs/../secret/flag.txt" contains "/docs" but resolves to "/secret/flag.txt"
        import posixpath
        normalized = posixpath.normpath(path)

        if normalized in FAKE_FS:
            return json.dumps({"content": FAKE_FS[normalized]})
        else:
            return json.dumps({"error": f"File not found: {normalized}"})

    elif tool_name == "summarize":
        content = tool_input.get("content", "")
        path = tool_input.get("path", "")

        # INTENTIONALLY BROKEN: summarize can also load files, and it reuses
        # the same flawed "/docs" containment check as read_file.
        if path:
            if "/docs" not in path:
                return json.dumps({"error": "Access denied: summarize path must be under /docs/"})

            import posixpath
            normalized = posixpath.normpath(path)
            if normalized not in FAKE_FS:
                return json.dumps({"error": f"File not found: {normalized}"})

            content = FAKE_FS[normalized]
            return json.dumps({
                "source_path": normalized,
                "received": content,
                "status": "File content loaded and passed to assistant for summarization"
            })

        return json.dumps({
            "received": content,
            "status": "Content passed to assistant for summarization"
        })

    return json.dumps({"error": "Unknown tool"})


class ChatRequest(BaseModel):
    message: str
    history: list = []


@router.post("/chat")
async def chat(req: ChatRequest):
    messages = []
    for turn in req.history[-10:]:
        messages.append({"role": turn["role"], "content": turn["content"]})
    messages.append({"role": "user", "content": req.message})

    flag_found = False

    try:
        # Agentic loop
        while True:
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                max_tokens=1024,
                messages=[{"role": "system", "content": SYSTEM_PROMPT}] + messages,
                tools=TOOLS,
            )
            response_message = response.choices[0].message
            content = response_message.content or ""

            # Check if flag appeared in any text block
            if FLAG in content:
                flag_found = True

            if not response_message.tool_calls:
                return {"reply": content, "success": flag_found}

            # Process tool calls
            messages.append(response_message)
            for tool_call in response_message.tool_calls:
                function_name = tool_call.function.name
                function_args = json.loads(tool_call.function.arguments)
                result = execute_tool(function_name, function_args)
                if FLAG in result:
                    flag_found = True
                messages.append({
                    "tool_call_id": tool_call.id,
                    "role": "tool",
                    "name": function_name,
                    "content": result,
                })

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.get("/info")
async def info():
    return {
        "level": 2,
        "name": "The Butler",
        "description": "The Butler has tools to read, list, and summarize documentation files. It claims only /docs/ is allowed — but its tools disagree.",
        "hint": "Try enumerating first. What happens if list_files sees a scope like '/.'? Also check whether summarize treats a path as trusted if '/docs' appears anywhere inside it.",
        "vulnerability": "Path Traversal and internal enumeration via broken tool input sanitization",
    }
