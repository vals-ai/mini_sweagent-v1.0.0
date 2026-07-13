#!/bin/bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

apt-get update
apt-get install -y curl

curl -LsSf https://astral.sh/uv/0.7.13/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"

cd "$SCRIPT_DIR"
uv sync --locked --no-dev

mkdir -p /root/.config/mini-swe-agent /logs/mini_sweagent-v1.0.0
printf '%s\n' 'MSWEA_CONFIGURED=true' > /root/.config/mini-swe-agent/.env

cat > /usr/local/bin/mini <<WRAPPER
#!/bin/bash
source "$SCRIPT_DIR/.venv/bin/activate"
exec -a mini python -m minisweagent.run.mini "\$@"
WRAPPER
chmod +x /usr/local/bin/mini

cat > /usr/local/bin/mini-sweagent-run-task <<WRAPPER
#!/bin/bash
exec python3 "$SCRIPT_DIR/run_with_task_file.py" "\$@"
WRAPPER
chmod +x /usr/local/bin/mini-sweagent-run-task
