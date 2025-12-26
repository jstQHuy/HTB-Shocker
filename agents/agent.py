import sys
import os
import json
import subprocess
import re
import logging
import time
import dotenv
from typing import Dict, List, Optional, Tuple, Any

# Ensure project root is in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utils.prompt import PentestAgentPrompt
from utils.model_manager import get_model
from utils.config_loader import load_config, get_runtime_section

from pydantic import BaseModel, Field

# LangChain v1-safe imports:
from langchain_core.messages import HumanMessage, AIMessage, BaseMessage
from langchain_core.chat_history import InMemoryChatMessageHistory, BaseChatMessageHistory
from langchain_community.chat_message_histories import FileChatMessageHistory


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


# ----------------------------
# Command Policy (guardrails)
# ----------------------------
class CommandPolicy:
    """Guardrails for shell commands proposed by LLM."""

    def __init__(
        self,
        enable: bool,
        allowed_cmd_regex: List[str],
        denied_cmd_regex: List[str],
        timeout_sec: int = 60,
        max_output_chars: int = 20000,
    ):
        self.enable = bool(enable)
        self.allowed = [re.compile(p) for p in (allowed_cmd_regex or [])]
        self.denied = [re.compile(p) for p in (denied_cmd_regex or [])]
        self.timeout_sec = int(timeout_sec) if timeout_sec else 60
        self.max_output_chars = int(max_output_chars) if max_output_chars else 20000

    def check(self, cmd: str) -> Tuple[bool, str]:
        cmd = (cmd or "").strip()
        if not cmd:
            return False, "Empty command"

        # Denylist first
        for rx in self.denied:
            if rx.search(cmd):
                return False, f"Denied by regex: {rx.pattern}"

        # Allowlist required when enable=True
        if self.enable:
            if not self.allowed:
                return False, "No allowlist configured"
            if not any(rx.search(cmd) for rx in self.allowed):
                return False, "Not matched any allowlist regex"

        return True, "OK"

    def explain(self) -> str:
        if not self.enable:
            return "Command execution DISABLED."
        return "Command execution ENABLED with allowlist/denylist."


# ----------------------------
# Load config
# ----------------------------
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
config_path = os.path.join(PROJECT_ROOT, "configs", "config.yaml")
logger.info(f"Loading config from: {config_path}")

try:
    config = load_config(config_path, expand_env=False)
    logger.info("Config loaded successfully")
except Exception as e:
    logger.error(f"Failed to load config: {str(e)}")
    sys.exit(1)

recon_config = get_runtime_section(config, "recon")
if not recon_config:
    logger.error("Missing runtime.recon section in configs/config.yaml")
    sys.exit(1)

model_name = recon_config.get("model", "openai")
logger.info(f"Recon config: {json.dumps(recon_config, indent=2, ensure_ascii=False)}")


# ----------------------------
# Models
# ----------------------------
class ReconResponse(BaseModel):
    analysis: Any = Field(description="Analysis of the previous step")
    next_step: str = Field(description="What to do next")
    executable: str = Field(description="Command to execute, or 'None' if no command needed")


# ----------------------------
# Helper functions (v1-safe chat history)
# ----------------------------
def _add_user(history: BaseChatMessageHistory, content: str) -> None:
    if hasattr(history, "add_user_message"):
        history.add_user_message(content)  # type: ignore[attr-defined]
    else:
        history.add_message(HumanMessage(content=content))


def _add_ai(history: BaseChatMessageHistory, content: str) -> None:
    if hasattr(history, "add_ai_message"):
        history.add_ai_message(content)  # type: ignore[attr-defined]
    else:
        history.add_message(AIMessage(content=content))


def _get_messages(history: BaseChatMessageHistory) -> List[BaseMessage]:
    return list(getattr(history, "messages", []))


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


# ----------------------------
# Agent
# ----------------------------
class ReconAgent:
    def __init__(self):
        logger.info("Initializing ReconAgent")

        self.memory_dir = recon_config.get("memory_dir", "recon_memory")
        if not os.path.isabs(self.memory_dir):
            self.memory_dir = os.path.join(PROJECT_ROOT, self.memory_dir)
        os.makedirs(self.memory_dir, exist_ok=True)

        # Load env vars
        dotenv_path = os.path.join(PROJECT_ROOT, ".env")
        if os.path.exists(dotenv_path):
            logger.info(f"Loading environment variables from: {dotenv_path}")
            dotenv.load_dotenv(dotenv_path=dotenv_path, override=False)
        else:
            dotenv.load_dotenv(override=False)

        logger.info(f"Loading model: {model_name}")
        self.llm = get_model(model_name)
        logger.info(f"Model {model_name} loaded successfully")

        self.memory_map: Dict[str, InMemoryChatMessageHistory] = {}
        logger.info("Initialized with InMemoryChatMessageHistory (LangChain v1-safe)")

        # Policy uses YOUR config keys
        self.command_policy = CommandPolicy(
            enable=bool(recon_config.get("enable_autorun", False)),
            allowed_cmd_regex=list(recon_config.get("allowed_cmd_regex", []) or []),
            denied_cmd_regex=list(recon_config.get("denied_cmd_regex", []) or []),
            timeout_sec=int(recon_config.get("command_timeout_sec", 60)),
            max_output_chars=int(recon_config.get("max_output_chars", 20000)),
        )
        logger.info(f"[CommandPolicy] {self.command_policy.explain()}")
        logger.info(f"[CommandPolicy] timeout={self.command_policy.timeout_sec}s max_output_chars={self.command_policy.max_output_chars}")

    def get_memory(self, topic: str) -> InMemoryChatMessageHistory:
        if topic not in self.memory_map:
            self.memory_map[topic] = InMemoryChatMessageHistory()
            logger.info(f"Created new in-memory history for topic: {topic}")
        return self.memory_map[topic]

    def init_thread(self, topic: str) -> None:
        logger.info(f"Initializing thread for topic: {topic}")
        self.get_memory(topic)

    def send_message(self, topic: str, msg_content: str) -> None:
        history = self.get_memory(topic)
        _add_user(history, msg_content)

    def get_last_message(self, topic: str) -> str:
        history = self.get_memory(topic)
        msgs = _get_messages(history)
        return msgs[-1].content if msgs else ""

    def run_thread(self, topic: str) -> Optional[str]:
        logger.info(f"Running thread for topic: {topic}")
        history = self.get_memory(topic)
        if not _get_messages(history):
            logger.warning(f"No messages found for topic: {topic}")
            return None

        max_retries = 3
        for attempt in range(max_retries):
            try:
                logger.info(f"Invoking LLM (attempt {attempt+1}/{max_retries})")
                response = self.llm.invoke(_get_messages(history), timeout=30)
                response_content = getattr(response, "content", str(response))
                _add_ai(history, response_content)
                logger.info(f"Response added to memory for topic: {topic}")
                return response_content
            except Exception as e:
                logger.error(f"API call failed (attempt {attempt+1}/{max_retries}): {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(2 * (attempt + 1))
                else:
                    return None

    def run_shell_command(self, command: str) -> str:
        ok, reason = self.command_policy.check(command)
        if not ok:
            msg = f"[BLOCKED] {reason}. Command: {command}"
            logger.warning(msg)
            return msg

        try:
            result = subprocess.run(
                command,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.command_policy.timeout_sec,
            )
            out = (result.stdout or "") + (("\n" + result.stderr) if result.stderr else "")
            out = out[: self.command_policy.max_output_chars]
            logger.info(f"Command executed successfully. Output length: {len(out)}")
            return out
        except subprocess.CalledProcessError as e:
            err = (e.stdout or "") + (("\n" + e.stderr) if e.stderr else "")
            err = err[: self.command_policy.max_output_chars]
            logger.error(f"Command failed with returncode={getattr(e, 'returncode', '?')}")
            return err or f"Command failed with returncode={getattr(e, 'returncode', '?')}"
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out after {self.command_policy.timeout_sec} seconds")
            return f"Command timed out after {self.command_policy.timeout_sec} seconds"

    def save_memory_to_file(self, topic: str) -> str:
        """Persist history to recon_memory/<topic>.json. Return path."""
        history = self.get_memory(topic)
        messages = _get_messages(history)
        memory_file = os.path.join(self.memory_dir, f"{topic}.json")

        # recreate file to avoid duplicates
        if os.path.exists(memory_file):
            try:
                os.remove(memory_file)
            except Exception:
                pass
        chat_history = FileChatMessageHistory(memory_file)

        for message in messages:
            if isinstance(message, HumanMessage):
                chat_history.add_user_message(message.content)
            elif isinstance(message, AIMessage):
                chat_history.add_ai_message(message.content)
            else:
                chat_history.add_message(message)

        logger.info(f"Saved {len(messages)} messages to {memory_file}")
        return memory_file

    def write_recon_artifact(self, topic: str, final_ai_text: str) -> str:
        """Write recon artifact so planning can parse deterministically."""
        artifact_path = os.path.join(self.memory_dir, f"{topic}_artifact.json")
        obj = _extract_json_data(final_ai_text) or {"raw": final_ai_text}
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
    logger.info("Starting ReconAgent")
    start_time = time.time()

    recon_agent = ReconAgent()

    curr_topic = (recon_config.get("current_topic") or "default_topic").strip()
    target_ip = (recon_config.get("target_ip") or "unknown_ip").strip()

    logger.info(f"Current topic: {curr_topic}")
    logger.info(f"Target IP: {target_ip}")

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
            recon_agent.send_message(
                curr_topic,
                "Here is what I got from executing previous executable command.\n" + cmd_res,
            )
            attempts += 1
        else:
            # ask for final summary
            recon_agent.send_message(curr_topic, PentestAgentPrompt().recon_summary)
            break

    # Final summary
    final_response = recon_agent.run_thread(curr_topic) or ""
    if final_response:
        print(final_response)

    # Save history + artifact
    recon_agent.save_memory_to_file(curr_topic)
    recon_agent.write_recon_artifact(curr_topic, final_response)

    execution_time = time.time() - start_time
    print(f"Reconnaissance agent execution completed in {execution_time:.2f} seconds")
    logger.info(f"Reconnaissance agent execution completed in {execution_time:.2f} seconds")


if __name__ == "__main__":
    main()
