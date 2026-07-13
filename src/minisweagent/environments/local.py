import os
import platform
import signal
import subprocess
import threading
from typing import Any

from pydantic import BaseModel

from minisweagent.exceptions import Submitted
from minisweagent.utils.serialize import recursive_merge


class LocalEnvironmentConfig(BaseModel):
    cwd: str = ""
    env: dict[str, str] = {}
    timeout: int = 30


class LocalEnvironment:
    def __init__(self, *, config_class: type = LocalEnvironmentConfig, **kwargs):
        """This class executes bash commands directly on the local machine."""
        self.config = config_class(**kwargs)

    def execute(self, action: dict, cwd: str = "", *, timeout: int | None = None) -> dict[str, Any]:
        """Execute a command in the local environment and return the result as a dict."""
        command = action.get("command", "")
        cwd = cwd or self.config.cwd or os.getcwd()
        effective_timeout = timeout or self.config.timeout
        try:
            p = subprocess.Popen(
                command,
                shell=True,
                cwd=cwd,
                env=os.environ | self.config.env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            timed_out = False

            def _kill_on_timeout():
                nonlocal timed_out
                timed_out = True
                try:
                    os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                except OSError:
                    pass
                try:
                    p.stdout.close()
                except OSError:
                    pass

            timer = threading.Timer(effective_timeout, _kill_on_timeout)
            timer.start()
            try:
                stdout, _ = p.communicate()
            except Exception:
                stdout = b""
            finally:
                timer.cancel()

            if timed_out:
                partial = stdout.decode("utf-8", errors="replace") if isinstance(stdout, bytes) else (stdout or "")
                output = {
                    "output": partial,
                    "returncode": -1,
                    "exception_info": f"An error occurred while executing the command: timed out after {effective_timeout} seconds",
                    "extra": {"exception_type": "TimeoutExpired", "exception": f"timed out after {effective_timeout} seconds"},
                }
            else:
                output = {"output": stdout.decode("utf-8", errors="replace") if isinstance(stdout, bytes) else (stdout or ""), "returncode": p.returncode, "exception_info": ""}
        except Exception as e:
            raw_output = getattr(e, "output", None)
            raw_output = (
                raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else (raw_output or "")
            )
            output = {
                "output": raw_output,
                "returncode": -1,
                "exception_info": f"An error occurred while executing the command: {e}",
                "extra": {"exception_type": type(e).__name__, "exception": str(e)},
            }
        self._check_finished(output)
        return output

    def _check_finished(self, output: dict):
        """Raises Submitted if the output indicates task completion."""
        lines = output.get("output", "").lstrip().splitlines(keepends=True)
        if lines and lines[0].strip() == "COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT" and output["returncode"] == 0:
            submission = "".join(lines[1:])
            raise Submitted(
                {
                    "role": "exit",
                    "content": submission,
                    "extra": {"exit_status": "Submitted", "submission": submission},
                }
            )

    def get_template_vars(self, **kwargs) -> dict[str, Any]:
        return recursive_merge(self.config.model_dump(), platform.uname()._asdict(), os.environ, kwargs)

    def serialize(self) -> dict:
        return {
            "info": {
                "config": {
                    "environment": self.config.model_dump(mode="json"),
                    "environment_type": f"{self.__class__.__module__}.{self.__class__.__name__}",
                }
            }
        }
