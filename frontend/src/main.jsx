import React from "react";
import { createRoot } from "react-dom/client";
import "highlight.js/styles/github-dark.css";
import "./styles.css";
import App from "./App.jsx";

const shieldFavicon =
  "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 128 128'%3E%3Crect width='128' height='128' rx='30' fill='%23131314'/%3E%3Cpath d='M64 12 104 29v30c0 27-17 48-40 57-23-9-40-30-40-57V29z' fill='%234285F4'/%3E%3Cpath d='M45 65l12 13 28-31' fill='none' stroke='white' stroke-width='9' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E";

function installShieldFavicon() {
  document
    .querySelectorAll("link[rel='icon'], link[rel='shortcut icon'], link[rel='apple-touch-icon']")
    .forEach((node) => node.remove());

  [
    { rel: "icon", type: "image/svg+xml", href: shieldFavicon },
    { rel: "shortcut icon", href: shieldFavicon },
    { rel: "apple-touch-icon", href: shieldFavicon },
  ].forEach((attributes) => {
    const link = document.createElement("link");
    Object.entries(attributes).forEach(([key, value]) => link.setAttribute(key, value));
    document.head.appendChild(link);
  });
}

installShieldFavicon();

class RootErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  render() {
    if (this.state.error) {
      return (
        <div className="boot-error">
          <div className="boot-error-card">
            <span>SECAI boot guard</span>
            <h1>The interface hit a browser-side render error.</h1>
            <p>
              This is usually caused by stale local session state after a UI
              upgrade. Clear the browser history cache below and refresh.
            </p>
            <pre>{String(this.state.error?.message || this.state.error)}</pre>
            <button
              onClick={() => {
                localStorage.removeItem("agent_history");
                window.location.reload();
              }}
            >
              Clear SECAI local history and reload
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <RootErrorBoundary>
      <App />
    </RootErrorBoundary>
  </React.StrictMode>,
);
