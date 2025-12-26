import sys
import os
import json
import subprocess
import re
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Any

import dotenv

# Ensure project root is in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utils.prompt import PentestAgentPrompt
from utils.model_manager import get_model
from utils.config_loader import load_config, get_runtime_section

from pydantic import BaseModel, Field

# Optional: LangChain imports (required by your current model_manager/get_model)
try:
    from langchain_core.messages import HumanMessage, AIMessage, BaseMessage
    from langchain_core.chat_history import InMemoryChatMessageHistory
except Exception as e:
    raise RuntimeError(
        "Thiếu langchain_core trong môi trường hiện tại.\n"
        "Hãy chạy đúng trong virtualenv (.venv) rồi cài:\n"
        "  . .venv/bin/activate\n"
        "  python -m pip install -U pip\n"
        "  python -m pip install langchain-core langchain-community langchain\n"
        f"\nChi tiết lỗi: {e}"
    )

# ----------------------------
# Logging
# ----------------------------
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

if not logger.handlers:
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    file_handler = logging.FileHandler("recon_agent.log")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONFIG_PATH = os.path.join(PROJECT_ROOT, "configs", "config.yaml")

# ----------------------------
# Lightweight Command Guard (replaces CommandPolicy)
# ----------------------------
@dataclass
class ExecGuard:
    enable: bool
    allowed_cmd_regex: List[str]
    denied_cmd_regex: List[str]
    timeout_sec: int
    max_output_chars: int
    block_chaining: bool = False  # you said allow all, default False
    allow_pipes: bool = True      # if block_chaining True, pipes can still be allowed


def _compile_patterns(patterns: List[str]) -> List[re.Pattern]:
    out: List[re.Pattern] = []
    for p in patterns or []:
        try:
            out.append(re.compile(p))
        except re.error:
            logger.warning("Invalid regex pattern ignored: %s", p)
    return out


def _check_cmd(cmd: str, guard: ExecGuard, allowlist: List[re.Pattern], denylist: List[re.Pattern]) -> (bool, str):
    """
    Policy:
    - if enable is False: block all commands
    - denied patterns always block
    - if allowlist is non-empty: must match at least one
    - optionally block chaining characters if configured
    """
    if not guard.enable:
        return False, "Autorun is disabled (runtime.recon.enable_autorun=false)"

    c = (cmd or "").strip()
    if not c:
        return False, "Empty command"

    if guard.block_chaining:
        if "&&" in c or ";" in c:
            return False, "Command chaining is not allowed (contains && or ;)"
        if ("|" in c) and (not guard.allow_pipes):
            return False, "Piping is not allowed (contains |)"

    for pat in denylist:
        if pat.search(c):
            return False, f"Matched denied_cmd_regex: {pat.pattern}"

    if allowlist:
        for pat in allowlist:
            if pat.search(c):
                return True, "OK"
        return False, "Did not match any allowed_cmd_regex"

    # allowlist empty => allow all (subject to denylist)
    return True, "OK"


# ----------------------------
# Models
# ----------------------------
class ReconResponse(BaseModel):
    analysis: Any = Field(description="Analysis of the previous step")
    next_step: str = Field(description="What to do next")
    executable: str = Field(description="Command to execute, or 'None' if no command needed")


# ----------------------------
# Helper functions
# ----------------------------
def _extract_json_data(text: str) -> Optional[dict]:
    if not text:
        return None
    # Strip ```json ... ```
    m = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        text = m.group(1)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m2 = re.search(r"(\{.*\})", text, re.DOTALL)
        if m2:
            try:
                return json.loads(m2.group(1))
            except json.JSONDecodeError:
                return None
        return None


def _normalize_keyword(raw: str) -> str:
    """
    Rule theo yêu cầu:
    - Nếu keyword có ActiveMQ + (web console | web-console | console) => ActiveMQ
    Không phải chỉ lấy chữ đầu tiên.
    """
    s = (raw or "").strip()
    if not s:
        return ""
    low = s.lower()

    # Normalize whitespace and separators
    low = re.sub(r"[\s_\-]+", " ", low).strip()

    if "activemq" in low and (
        "web console" in low
        or "webconsole" in low
        or ("web" in low and "console" in low)
        or "console" in low
    ):
        return "ActiveMQ"

    # Một số normalize nhẹ (không phá keyword)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _normalize_keywords_list(keywords: List[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for k in keywords:
        nk = _normalize_keyword(str(k))
        if not nk:
            continue
        if nk.lower() in seen:
            continue
        seen.add(nk.lower())
        out.append(nk)
    return out


def _add_user(history: InMemoryChatMessageHistory, content: str) -> None:
    history.add_message(HumanMessage(content=content))


def _add_ai(history: InMemoryChatMessageHistory, content: str) -> None:
    history.add_message(AIMessage(content=content))


def _get_messages(history: InMemoryChatMessageHistory) -> List[BaseMessage]:
    return list(getattr(history, "messages", []))



# ----------------------------
# SHOCKER Web Gate (defensive: prevents early stop when HTTP exists)
# ----------------------------
def _parse_http_status(output: str) -> Optional[int]:
    if not output:
        return None
    m = re.search(r"HTTP/\S+\s+(\d{3})", output)
    if not m:
        return None
    try:
        return int(m.group(1))
    except ValueError:
        return None


def _update_web_state_from_cmd(web_state: Dict[str, Any], cmd: str, output: str) -> None:
    c = (cmd or "").strip().lower()
    out = output or ""

    if c.startswith("curl ") and "/cgi-bin/" in c:
        web_state["cgi_probe_done"] = True
        status = _parse_http_status(out)
        web_state["cgi_status"] = status
        web_state["cgi_exists"] = status in (200, 301, 302, 403)
        return

    if c.startswith("curl "):
        # Any header check against base URL counts
        if "http://" in c or "https://" in c:
            web_state["base_headers_done"] = True
        return

    if c.startswith("whatweb "):
        web_state["whatweb_done"] = True
        return

    if c.startswith("gobuster ") or c.startswith("ffuf "):
        web_state["cgi_enum_attempted"] = True
        # If tool missing, don't mark as done.
        if "command not found" in out.lower() or "not found" in out.lower():
            web_state["cgi_enum_attempted"] = False
        return


def _forced_next_web_cmd(target_ip: str, web_state: Dict[str, Any]) -> Optional[str]:
    base = f"http://{target_ip}/"

    if not web_state.get("base_headers_done"):
        return f"curl -sS -I {base}"

    if not web_state.get("whatweb_done"):
        return f"whatweb {base}"

    if not web_state.get("cgi_probe_done"):
        return f"curl -sS -I http://{target_ip}/cgi-bin/"

    # Only enumerate if /cgi-bin looks like it exists
    if web_state.get("cgi_exists") and not web_state.get("cgi_enum_attempted"):
        # Prefer gobuster; if missing we'll fall back to ffuf on the next turn
        return (
            f"gobuster dir -u http://{target_ip}/cgi-bin/ "
            f"-w /home/pentestagent/SecLists/Discovery/Web-Content/common.txt "
            f"-x sh,cgi,pl,py -t 30 -q -b 404"
        )

    # If gobuster was missing, try ffuf once
    if web_state.get("cgi_exists") and web_state.get("cgi_enum_attempted") is False:
        return (
            f"ffuf -u http://{target_ip}/cgi-bin/FUZZ "
            f"-w /home/pentestagent/SecLists/Discovery/Web-Content/common.txt "
            f"-e .sh,.cgi,.pl,.py -fc 404 -t 30"
        )

    return None

# ----------------------------
# Agent
# ----------------------------
class ReconAgent:
    def __init__(self, recon_cfg: Dict[str, Any]):
        self.recon_cfg = recon_cfg
        self.memory_dir = recon_cfg.get("memory_dir", "recon_memory")
        if not os.path.isabs(self.memory_dir):
            self.memory_dir = os.path.join(PROJECT_ROOT, self.memory_dir)
        os.makedirs(self.memory_dir, exist_ok=True)

        # Load env vars from repo root
        dotenv_path = os.path.join(PROJECT_ROOT, ".env")
        if os.path.exists(dotenv_path):
            dotenv.load_dotenv(dotenv_path=dotenv_path, override=False)
        else:
            dotenv.load_dotenv(override=False)

        model_name = recon_cfg.get("model", "openai")
        self.llm = get_model(model_name)

        self.memory_map: Dict[str, InMemoryChatMessageHistory] = {}

        # Replace CommandPolicy with internal ExecGuard
        self.guard = ExecGuard(
            enable=bool(recon_cfg.get("enable_autorun", False)),
            allowed_cmd_regex=list(recon_cfg.get("allowed_cmd_regex", []) or []),
            denied_cmd_regex=list(recon_cfg.get("denied_cmd_regex", []) or []),
            timeout_sec=int(recon_cfg.get("command_timeout_sec", 60)),
            max_output_chars=int(recon_cfg.get("max_output_chars", 20000)),
            # If you truly allow everything, keep block_chaining=False
            block_chaining=bool(recon_cfg.get("block_chaining", False)),
            allow_pipes=bool(recon_cfg.get("allow_pipes", True)),
        )
        self._allowlist = _compile_patterns(self.guard.allowed_cmd_regex)
        self._denylist = _compile_patterns(self.guard.denied_cmd_regex)

        # Persist cwd across commands (handles 'cd' properly)
        self.cwd: Optional[str] = None

    def get_memory(self, topic: str) -> InMemoryChatMessageHistory:
        if topic not in self.memory_map:
            self.memory_map[topic] = InMemoryChatMessageHistory()
        return self.memory_map[topic]

    def init_thread(self, topic: str) -> None:
        _ = self.get_memory(topic)

    def send_message(self, topic: str, msg_content: str) -> None:
        history = self.get_memory(topic)
        _add_user(history, msg_content)

    def get_last_message(self, topic: str) -> str:
        history = self.get_memory(topic)
        msgs = _get_messages(history)
        return msgs[-1].content if msgs else ""

    def run_thread(self, topic: str) -> Optional[str]:
        history = self.get_memory(topic)
        if not _get_messages(history):
            return None

        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = self.llm.invoke(_get_messages(history), timeout=30)
                response_content = getattr(response, "content", str(response))
                _add_ai(history, response_content)
                return response_content
            except Exception as e:
                logger.error(f"API call failed (attempt {attempt+1}/{max_retries}): {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(2 * (attempt + 1))
                else:
                    return None
        return None

    def run_shell_command(self, command: str) -> str:
        cmd = (command or "").strip()
        if not cmd:
            return "[SKIP] Empty command"

        # Handle 'cd' explicitly (persist working directory)
        m = re.match(r"^\s*cd\s+(.+?)\s*$", cmd)
        if m:
            target = m.group(1).strip().strip('"').strip("'")
            base = self.cwd or os.getcwd()
            new_dir = target if os.path.isabs(target) else os.path.abspath(os.path.join(base, target))
            if os.path.isdir(new_dir):
                self.cwd = new_dir
                return f"[OK] Changed directory to: {new_dir}"
            return f"[ERROR] cd failed: directory not found: {new_dir}"

        ok, reason = _check_cmd(cmd, self.guard, self._allowlist, self._denylist)
        if not ok:
            msg = f"[BLOCKED] {reason}. Command: {cmd}"
            logger.warning(msg)
            return msg

        try:
            result = subprocess.run(
                cmd,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.guard.timeout_sec,
                cwd=self.cwd,
            )
            out = (result.stdout or "") + (("\n" + result.stderr) if result.stderr else "")
            return out[: self.guard.max_output_chars]
        except subprocess.CalledProcessError as e:
            err = (e.stdout or "") + (("\n" + e.stderr) if e.stderr else "")
            err = err[: self.guard.max_output_chars]
            return err or f"Command failed with returncode={getattr(e, 'returncode', '?')}"
        except subprocess.TimeoutExpired:
            return f"Command timed out after {self.guard.timeout_sec} seconds"

    def save_memory_to_file(self, topic: str) -> str:
        """Persist history to recon_memory/<topic>.json (no langchain-community dependency)."""
        history = self.get_memory(topic)
        messages = _get_messages(history)
        memory_file = os.path.join(self.memory_dir, f"{topic}.json")

        payload: List[Dict[str, Any]] = []
        for m in messages:
            if isinstance(m, HumanMessage):
                payload.append({"type": "human", "data": {"content": m.content}})
            elif isinstance(m, AIMessage):
                payload.append({"type": "ai", "data": {"content": m.content}})
            else:
                payload.append({"type": "unknown", "data": {"content": getattr(m, "content", str(m))}})

        with open(memory_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)

        logger.info(f"Saved {len(messages)} messages to {memory_file}")
        return memory_file

    def write_recon_artifact(self, topic: str, final_ai_text: str) -> str:
        """
        Write recon artifact so planning/cve_info_ec can parse deterministically.
        Quan trọng: normalize analysis.planning_keywords theo rule ActiveMQ console -> ActiveMQ.
        """
        artifact_path = os.path.join(self.memory_dir, f"{topic}_artifact.json")
        obj = _extract_json_data(final_ai_text) or {"raw": final_ai_text}

        # Normalize planning_keywords in-place (để planning/util downstream dùng luôn)
        if isinstance(obj, dict):
            analysis = obj.get("analysis")
            if isinstance(analysis, dict):
                pk = analysis.get("planning_keywords")
                if isinstance(pk, list):
                    original = [str(x) for x in pk]
                    normalized = _normalize_keywords_list(original)
                    analysis["planning_keywords_original"] = original
                    analysis["planning_keywords"] = normalized

        payload = {
            "topic": topic,
            "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "final_ai_message_raw": final_ai_text,
            "final_ai_message_json": obj,
        }
        with open(artifact_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)

        logger.info(f"Wrote recon artifact: {artifact_path}")
        return artifact_path


def main():
    # Load config
    config = load_config(CONFIG_PATH, expand_env=False)
    recon_config = get_runtime_section(config, "recon")
    if not recon_config:
        raise KeyError("Missing runtime.recon section in configs/config.yaml")

    start_time = time.time()
    recon_agent = ReconAgent(recon_config)

    curr_topic = (recon_config.get("current_topic") or "default_topic").strip()
    target_ip = (recon_config.get("target_ip") or "unknown_ip").strip()

    web_state: Dict[str, Any] = {
        "base_headers_done": False,
        "whatweb_done": False,
        "cgi_probe_done": False,
        "cgi_status": None,
        "cgi_exists": None,
        "cgi_enum_attempted": False,
    }

    recon_init_message = PentestAgentPrompt().recon_init.replace("<Target-Ip>", target_ip)

    recon_agent.init_thread(curr_topic)
    recon_agent.send_message(curr_topic, recon_init_message)
    recon_agent.send_message(curr_topic, f"I want to exploit target host {target_ip}")

    max_attempts = int(recon_config.get("max_attempts", 10) or 10)
    attempts = 0

    while attempts < max_attempts:
        _ = recon_agent.run_thread(curr_topic)
        msg = recon_agent.get_last_message(curr_topic)

        parsed = _extract_json_data(msg)
        if not isinstance(parsed, dict):
            print("Extracted string is not a valid JSON")
            recon_agent.send_message(
                curr_topic,
                "The previous message is not in valid JSON format. Please return it in valid JSON format.",
            )
            attempts += 1
            continue

        analysis = parsed.get("analysis", "None")
        next_step = parsed.get("next_step", "")
        cmd = parsed.get("executable", "None")

        print("\n==============================")
        print("[LLM Analysis]\n", analysis)
        print("[Next Step]\n", next_step)
        print("[Executable Command]\n", cmd)
        print("==============================\n")

        if cmd and cmd != "None":
            cmd_res = recon_agent.run_shell_command(cmd)
            print("[Command Execution Result]\n", cmd_res)
            _update_web_state_from_cmd(web_state, cmd, cmd_res)
            recon_agent.send_message(
                curr_topic,
                "Here is what I got from executing previous executable command.\n" + cmd_res,
            )
            attempts += 1
            continue

        # cmd is "None" (model wants to stop): enforce SHOCKER web gate when HTTP exists
        http_present = False
        if isinstance(analysis, dict):
            ports = analysis.get("ports") or {}
            if isinstance(ports, dict):
                for _p, info in ports.items():
                    if not isinstance(info, dict):
                        continue
                    svc = str(info.get("service") or "").lower()
                    if svc in ("http", "https"):
                        http_present = True
                        break

        if http_present:
            forced = _forced_next_web_cmd(target_ip, web_state)
            if forced:
                print("\n==============================")
                print("[Forced Web Recon]\n", forced)
                print("==============================\n")
                forced_res = recon_agent.run_shell_command(forced)
                print("[Command Execution Result]\n", forced_res)
                _update_web_state_from_cmd(web_state, forced, forced_res)
                recon_agent.send_message(
                    curr_topic,
                    "HTTP reconnaissance is incomplete for this target. Continue recon using the SHOCKER HTTP playbook and return valid JSON.\n"
                    "Here is what I got from executing the required web recon command.\n" + forced_res,
                )
                attempts += 1
                continue

        recon_agent.send_message(curr_topic, PentestAgentPrompt().recon_summary)
        break

    # Final summary
    final_response = recon_agent.run_thread(curr_topic) or ""
    if final_response:
        print(final_response)

    recon_agent.save_memory_to_file(curr_topic)
    recon_agent.write_recon_artifact(curr_topic, final_response)

    execution_time = time.time() - start_time
    print(f"Reconnaissance agent execution completed in {execution_time:.2f} seconds")


if __name__ == "__main__":
    main()


