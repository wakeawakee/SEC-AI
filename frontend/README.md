# SECAI React Chat Interface

This is the separated web frontend for the AI Security Assurance Agent.
It talks to the FastAPI bridge in `../backend_api.py`, which imports the shared
AI/security engine from `../app.py`.

## Local run

Recommended Docker path from the repository root:

```bash
docker compose up --build
```

Open:

```text
http://localhost:5173
```

Manual two-terminal path:

Terminal 1 — backend:

```bash
cd /home/bara/Security-Agent
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn backend_api:app --reload --host 0.0.0.0 --port 8000
```

Terminal 2 — frontend:

```bash
cd /home/bara/Security-Agent/frontend
npm install
npm run dev
```

Open:

```text
http://localhost:5173
```

## Runtime behavior

- Session history is stored in browser `localStorage` as `agent_history`.
- The left sidebar renders actual session state, not placeholder HTML.
- The title for each session is generated from the first 25 characters of the
  first user prompt.
- Every send creates a fresh `AbortController`.
- The Stop button calls `abort()` on the active request and freezes the current
  streamed answer where it stopped.
- Text-like evidence files are read in-browser and sent as JSON.
- PDF/DOCX uploads are sent to `/analyze-upload`, where the Python backend uses
  the existing local extraction and sanitization path.

## API URL

By default the frontend calls:

```text
http://localhost:8000
```

Override it with:

```bash
VITE_AGENT_API_URL=https://your-deployed-agent.example.com npm run build
```

## Ollama provider troubleshooting

When running through Docker, the React app talks to FastAPI, and FastAPI talks
to Ollama. If Ollama runs on the host, it must listen beyond host-only loopback:

```bash
OLLAMA_HOST=0.0.0.0:11434 ollama serve
ollama pull nomic-embed-text
ollama pull llama3.2
```

Check backend connectivity:

```bash
curl http://localhost:8000/ollama-health
```

Or run the bundled Ollama sidecar from the repository root:

```bash
docker compose -f docker-compose.yml -f docker-compose.ollama.yml up --build
```
