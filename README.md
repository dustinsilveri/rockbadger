# llm-secret-detection


This uses Ollama to help find some secrets.
untar the testcase, (gitlab doesn't like me uploading secrets apparently.)

## Local Services

If you do not already have Ollama running on `localhost:11434`, start the optional Compose service:

```sh
docker compose --profile llm up -d ollama
```

The app defaults to:

```text
OLLAMA_URL=http://127.0.0.1:11434
OLLAMA_MODEL=qwen2.5-coder:1.5b
```

The app checks for the configured Ollama model at startup and pulls it if needed.

Use a different Ollama model:

```sh
OLLAMA_MODEL="qwen2.5-coder:7b" go run .
```

By default, the scanner uses both built-in local detectors and the LLM:

```sh
go run . ./path/to/scan
```

## Flags

- `--llm-only`: only use the LLM to identify secrets. Built-in local detectors are disabled.
- `--no-llm`: only use built-in local detectors. Ollama setup and LLM calls are skipped entirely.

Only use the LLM for secret detection, bypassing the built-in local detectors:

```sh
go run . --llm-only ./path/to/scan
```

Run without the LLM, using only the built-in local detectors:

```sh
go run . --no-llm ./path/to/scan
```
