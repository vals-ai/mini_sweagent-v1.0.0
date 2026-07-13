# Mini SWE-agent v1.0.0 for Valkyrie

Valkyrie packaging release v1.0.0 of [Mini SWE-agent](https://github.com/SWE-agent/mini-swe-agent) for SWE-bench tasks.

## Configuration

- Model: required public `model-library==0.1.26` key passed with `--model`, for example `openai/gpt-4o`
- Secrets: map the matching provider variable to an AWS secret name with `-s ENV_VAR AWS_SECRET_NAME`
- Supported credentials: `OPENAI_API_KEY` for OpenAI models and `ANTHROPIC_API_KEY` for Anthropic models
- Gateway: set both `MODEL_GATEWAY_URL` and `MODEL_GATEWAY_API_KEY`; partial configuration is rejected
- Valkyrie kwargs: none
- Final output: `/logs/mini_sweagent-v1.0.0`

## Usage with Valkyrie

Install the standalone public repository:

```bash
valkyrie agent install https://github.com/vals-ai/mini_sweagent-v1.0.0
```

After the registry PR is merged, install through the public registry:

```bash
valkyrie agent install https://github.com/vals-ai/public-agent-registry/tree/main/agents/mini_sweagent-v1.0.0
```

Run one SWE-bench task:

```bash
valkyrie run start \
  --benchmark swebench \
  --dataset default \
  --agent mini_sweagent-v1.0.0 \
  --model openai/gpt-4o \
  -s OPENAI_API_KEY YOUR_AWS_SECRET_NAME \
  --concurrency 1 \
  --task-ids astropy__astropy-7606
```

## Output Files

- `/logs/mini_sweagent-v1.0.0/trajectory.json`
- `/logs/mini_sweagent-v1.0.0/metrics_per_turn.json`
- `/logs/mini_sweagent-v1.0.0/metrics_total.json`

## Known Limitations

- Setup requires a Debian-based benchmark image with `apt-get`.
- Model support depends on `model-library==0.1.26` and the matching provider credential.

## License

MIT. See [LICENSE.md](LICENSE.md) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
