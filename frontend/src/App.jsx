import React, { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import ReactMarkdown from "react-markdown";
import rehypeHighlight from "rehype-highlight";
import remarkGfm from "remark-gfm";
import {
  ArrowUp,
  Bot,
  FileText,
  Paperclip,
  Plus,
  ShieldCheck,
  Square,
  Trash2,
  UserRound,
} from "lucide-react";

const API_BASE = import.meta.env.VITE_AGENT_API_URL || "http://localhost:8000";
const HISTORY_KEY = "agent_history";

const providerModels = {
  "Mock (offline)": "deterministic-rules",
  "Ollama (local)": "llama3.2",
  OpenAI: "gpt-4o-mini",
};

function nowIso() {
  return new Date().toISOString();
}

function newId(prefix = "id") {
  return `${prefix}_${globalThis.crypto?.randomUUID?.() || `${Date.now()}_${Math.random()}`}`;
}

function safeJsonParse(value, fallback) {
  try {
    return value ? JSON.parse(value) : fallback;
  } catch {
    return fallback;
  }
}

function loadHistory() {
  if (typeof localStorage === "undefined") return [];
  const sessions = safeJsonParse(localStorage.getItem(HISTORY_KEY), []);
  if (!Array.isArray(sessions)) return [];
  return sessions
    .filter((session) => session && typeof session === "object")
    .map((session) => ({
      id: String(session.id || newId("session")),
      title: String(session.title || "Untitled audit"),
      createdAt: session.createdAt || nowIso(),
      updatedAt: session.updatedAt || session.createdAt || nowIso(),
      messages: Array.isArray(session.messages)
        ? session.messages
            .filter((message) => message && typeof message === "object")
            .map((message) => ({
              id: String(message.id || newId("msg")),
              role: message.role === "user" ? "user" : "assistant",
              content: String(message.content || ""),
              createdAt: message.createdAt || nowIso(),
            }))
        : [],
    }));
}

function saveHistory(sessions) {
  localStorage.setItem(HISTORY_KEY, JSON.stringify(sessions.slice(0, 40)));
}

function sessionTitle(text) {
  const cleaned = text.replace(/\s+/g, " ").trim();
  return cleaned.length > 25 ? `${cleaned.slice(0, 25)}…` : cleaned || "Untitled audit";
}

function isClientTextFile(file) {
  return /\.(txt|md|log|csv|json)$/i.test(file?.name || "");
}

function MarkdownMessage({ content }) {
  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      rehypePlugins={[rehypeHighlight]}
      components={{
        table: ({ children }) => <div className="table-wrap"><table>{children}</table></div>,
        code: ({ inline, className, children, ...props }) =>
          inline ? (
            <code className="inline-code" {...props}>{children}</code>
          ) : (
            <code className={className} {...props}>{children}</code>
          ),
      }}
    >
      {content}
    </ReactMarkdown>
  );
}

function Sidebar({
  sessions,
  activeSessionId,
  onNewChat,
  onGoHome,
  onSelectSession,
  onDeleteSession,
}) {
  return (
    <aside className="sidebar">
      <div className="sidebar-top">
        <button
          className="brand-lockup"
          onClick={onGoHome}
          title="Go to SECAI home"
          aria-label="Go to SECAI home"
        >
          <div className="brand-orb"><ShieldCheck size={18} /></div>
          <div>
            <p className="eyebrow">SACC</p>
            <h1>SECAI Agent</h1>
          </div>
        </button>

        <button className="new-chat-button" onClick={onNewChat}>
          <Plus size={18} />
          <span>New Chat</span>
        </button>
      </div>

      <div className="session-region">
        <div className="session-label">Recent assurance sessions</div>
        <div className="session-list">
          {sessions.length === 0 ? (
            <div className="empty-history">
              Your real audit sessions will appear here after the first prompt.
            </div>
          ) : (
            sessions.map((session) => (
              <button
                className={`session-item ${session.id === activeSessionId ? "active" : ""}`}
                key={session.id}
                onClick={() => onSelectSession(session.id)}
                title={session.title}
              >
                <span className="session-title">{session.title}</span>
                <Trash2
                  className="session-delete"
                  size={15}
                  onClick={(event) => {
                    event.stopPropagation();
                    onDeleteSession(session.id);
                  }}
                />
              </button>
            ))
          )}
        </div>
      </div>

      <div className="profile-card">
        <div className="avatar"><UserRound size={17} /></div>
        <div>
          <strong>Demo analyst</strong>
          <span>Input redaction active</span>
        </div>
      </div>
    </aside>
  );
}

function Hero({ onQuickStart }) {
  const cards = [
    {
      icon: "🔐",
      title: "Audit access controls",
      prompt: "Assess our access control documentation against ISO 27001 clauses 4-10, Annex A access controls, and SOC 2 Type II evidence expectations.",
    },
    {
      icon: "📋",
      title: "SOC 2 offboarding SLA",
      prompt: "What evidence do we need to prove employee offboarding operated effectively during a SOC 2 Type II review period?",
    },
    {
      icon: "🌐",
      title: "Zero-trust architecture",
      prompt: "Explain how zero-trust segmentation, least privilege, SIEM monitoring, and encryption evidence map to ISO 27001 and SOC 2.",
    },
  ];

  return (
    <section className="hero">
      <h2>Your move, Analyst Bara!</h2>
      <p>How can SECAI assist your security assurance workflow today?</p>
      <div className="quick-grid">
        {cards.map((card) => (
          <button className="quick-card" key={card.title} onClick={() => onQuickStart(card.prompt)}>
            <span>{card.icon}</span>
            <strong>{card.title}</strong>
            <small>{card.prompt.slice(0, 82)}…</small>
          </button>
        ))}
      </div>
    </section>
  );
}

function MessageList({ messages, isGenerating }) {
  const endRef = useRef(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [messages]);

  if (messages.length === 0) return null;

  return (
    <div className="message-stack">
      {messages.map((message) => (
        <article className={`message-row ${message.role}`} key={message.id}>
          {message.role === "assistant" && (
            <div className="assistant-badge"><Bot size={17} /></div>
          )}
          <div className="message-bubble">
            {message.role === "assistant" ? (
              <MarkdownMessage content={message.content || " "} />
            ) : (
              <p>{message.content}</p>
            )}
          </div>
        </article>
      ))}
      {isGenerating && (
        <div className="generation-status">
          <span className="pulse-dot" />
          Streaming assurance analysis…
        </div>
      )}
      <div ref={endRef} />
    </div>
  );
}

function ChatComposer({
  input,
  setInput,
  isGenerating,
  onSend,
  onStop,
  attachedFile,
  setAttachedFile,
  provider,
  setProvider,
  model,
  setModel,
  mode,
  setMode,
}) {
  const textareaRef = useRef(null);
  const fileRef = useRef(null);

  useLayoutEffect(() => {
    const node = textareaRef.current;
    if (!node) return;
    node.style.height = "0px";
    node.style.height = `${Math.min(node.scrollHeight, 200)}px`;
  }, [input]);

  function handleKeyDown(event) {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      onSend();
    }
  }

  return (
    <div className="composer-shell">
      <div className="composer-controls">
        <button
          className={`mode-chip ${mode === "chat" ? "selected" : ""}`}
          onClick={() => setMode("chat")}
        >
          Chat
        </button>
        <button
          className={`mode-chip ${mode === "document" ? "selected" : ""}`}
          onClick={() => setMode("document")}
        >
          Document assessment
        </button>
        <select
          className="model-select"
          value={provider}
          onChange={(event) => {
            setProvider(event.target.value);
            setModel(providerModels[event.target.value]);
          }}
        >
          {Object.keys(providerModels).map((name) => (
            <option key={name} value={name}>{name}</option>
          ))}
        </select>
        <input
          className="model-input"
          value={model}
          disabled={provider === "Mock (offline)"}
          onChange={(event) => setModel(event.target.value)}
          aria-label="Model name"
        />
      </div>

      <div className="composer-pill">
        <input
          ref={fileRef}
          type="file"
          className="hidden-file"
          accept=".txt,.md,.log,.csv,.json,.pdf,.docx"
          onChange={(event) => setAttachedFile(event.target.files?.[0] || null)}
        />
        <button
          className="utility-button"
          title="Attach evidence"
          onClick={() => fileRef.current?.click()}
        >
          <Paperclip size={19} />
        </button>
        <textarea
          ref={textareaRef}
          value={input}
          rows={1}
          placeholder="Ask SECAI or paste security documentation…"
          onChange={(event) => setInput(event.target.value)}
          onKeyDown={handleKeyDown}
        />
        <button
          className={`action-button ${isGenerating ? "stop" : "send"}`}
          onClick={isGenerating ? onStop : onSend}
          aria-label={isGenerating ? "Stop generation" : "Send message"}
        >
          {isGenerating ? <Square size={16} fill="currentColor" /> : <ArrowUp size={19} />}
        </button>
      </div>

      {attachedFile && (
        <div className="attachment-chip">
          <FileText size={14} />
          <span>{attachedFile.name}</span>
          <button onClick={() => setAttachedFile(null)}>Remove</button>
        </div>
      )}
    </div>
  );
}

export default function App() {
  const initialHistoryRef = useRef(loadHistory());
  const [sessions, setSessions] = useState(initialHistoryRef.current);
  const [activeSessionId, setActiveSessionId] = useState(() => initialHistoryRef.current[0]?.id || null);
  const [input, setInput] = useState("");
  const [isGenerating, setIsGenerating] = useState(false);
  const [attachedFile, setAttachedFile] = useState(null);
  const [provider, setProvider] = useState("Mock (offline)");
  const [model, setModel] = useState(providerModels["Mock (offline)"]);
  const [mode, setMode] = useState("chat");
  const [homeVersion, setHomeVersion] = useState(0);
  const currentAbortController = useRef(null);

  useEffect(() => {
    saveHistory(sessions);
  }, [sessions]);

  const activeSession = useMemo(
    () => sessions.find((session) => session.id === activeSessionId) || null,
    [sessions, activeSessionId],
  );
  const messages = activeSession?.messages || [];

  function mutateSessions(updater) {
    setSessions((previous) => updater(previous).slice(0, 40));
  }

  function beginAssistantTurn(firstPrompt, userMessage, assistantMessage) {
    const existingSession = activeSessionId && sessions.some((session) => session.id === activeSessionId);
    const sessionId = existingSession ? activeSessionId : newId("session");
    const timestamp = nowIso();
    mutateSessions((previous) =>
      existingSession
        ? previous.map((session) =>
            session.id === sessionId
              ? {
                  ...session,
                  updatedAt: timestamp,
                  messages: [...session.messages, userMessage, assistantMessage],
                }
              : session,
          )
        : [
            {
              id: sessionId,
              title: sessionTitle(firstPrompt),
              createdAt: timestamp,
              updatedAt: timestamp,
              messages: [userMessage, assistantMessage],
            },
            ...previous,
          ],
    );
    setActiveSessionId(sessionId);
    return sessionId;
  }

  function appendAssistantChunk(sessionId, messageId, chunk) {
    mutateSessions((previous) =>
      previous.map((session) =>
        session.id === sessionId
          ? {
              ...session,
              updatedAt: nowIso(),
              messages: session.messages.map((message) =>
                message.id === messageId
                  ? { ...message, content: `${message.content}${chunk}` }
                  : message,
              ),
            }
          : session,
      ),
    );
  }

  async function buildRequestBody(text) {
    const payload = {
      message: text,
      mode,
      provider,
      model,
      document_text: "",
    };

    if (!attachedFile) return { type: "json", payload };

    if (isClientTextFile(attachedFile)) {
      payload.document_text = await attachedFile.text();
      payload.mode = mode === "chat" ? "document" : mode;
      return { type: "json", payload };
    }

    const formData = new FormData();
    formData.append("file", attachedFile);
    formData.append("message", text);
    formData.append("provider", provider);
    formData.append("model", model);
    return { type: "upload", payload: formData };
  }

  async function sendDocumentToAgent(overrideText) {
    const text = (overrideText ?? input).trim();
    if (isGenerating || (!text && !attachedFile)) return;

    const displayText = attachedFile ? `${text || "Assess attached evidence"}\n\n📎 ${attachedFile.name}` : text;
    const userMessage = {
      id: newId("msg"),
      role: "user",
      content: displayText,
      createdAt: nowIso(),
    };
    const assistantId = newId("msg");
    const assistantMessage = {
      id: assistantId,
      role: "assistant",
      content: "",
      createdAt: nowIso(),
    };

    const sessionId = beginAssistantTurn(text || attachedFile.name, userMessage, assistantMessage);
    setInput("");

    currentAbortController.current = new AbortController();
    setIsGenerating(true);

    try {
      const request = await buildRequestBody(text || `Assess ${attachedFile.name}`);
      const response = await fetch(
        `${API_BASE}${request.type === "upload" ? "/analyze-upload" : "/analyze"}`,
        {
          method: "POST",
          headers: request.type === "json" ? { "Content-Type": "application/json" } : undefined,
          body: request.type === "json" ? JSON.stringify(request.payload) : request.payload,
          signal: currentAbortController.current.signal,
        },
      );

      if (!response.ok) {
        const errorText = await response.text();
        const errorPayload = safeJsonParse(errorText, null);
        throw new Error(
          errorPayload?.detail || errorText || `Request failed with HTTP ${response.status}`,
        );
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        appendAssistantChunk(sessionId, assistantId, decoder.decode(value, { stream: true }));
      }
    } catch (error) {
      if (error.name !== "AbortError") {
        appendAssistantChunk(
          sessionId,
          assistantId,
          `\n\n**Request failed:** ${error.message}`,
        );
      }
    } finally {
      currentAbortController.current = null;
      setIsGenerating(false);
      setAttachedFile(null);
    }
  }

  function handleStopGeneration() {
    currentAbortController.current?.abort();
    currentAbortController.current = null;
    setIsGenerating(false);
  }

  function handleNewChat() {
    handleStopGeneration();
    setActiveSessionId(null);
    setInput("");
    setAttachedFile(null);
    setMode("chat");
  }

  function handleGoHome() {
    handleNewChat();
    setHomeVersion((version) => version + 1);
    window.history.replaceState(null, "", "/");
    window.requestAnimationFrame(() => window.scrollTo({ top: 0, left: 0, behavior: "smooth" }));
  }

  function handleDeleteSession(id) {
    setSessions((previous) => {
      const next = previous.filter((session) => session.id !== id);
      if (activeSessionId === id) {
        setActiveSessionId(next[0]?.id || null);
      }
      return next;
    });
  }

  return (
    <div className="app-shell">
      <Sidebar
        sessions={sessions}
        activeSessionId={activeSessionId}
        onNewChat={handleNewChat}
        onGoHome={handleGoHome}
        onSelectSession={setActiveSessionId}
        onDeleteSession={handleDeleteSession}
      />

      <main className="main-workspace">
        <div className="top-glow" />
        <div className="message-scroll" key={activeSessionId || `home-${homeVersion}`}>
          {messages.length === 0 ? (
            <Hero onQuickStart={sendDocumentToAgent} />
          ) : (
            <MessageList messages={messages} isGenerating={isGenerating} />
          )}
        </div>

        <ChatComposer
          input={input}
          setInput={setInput}
          isGenerating={isGenerating}
          onSend={() => sendDocumentToAgent()}
          onStop={handleStopGeneration}
          attachedFile={attachedFile}
          setAttachedFile={setAttachedFile}
          provider={provider}
          setProvider={setProvider}
          model={model}
          setModel={setModel}
          mode={mode}
          setMode={setMode}
        />
      </main>
    </div>
  );
}
