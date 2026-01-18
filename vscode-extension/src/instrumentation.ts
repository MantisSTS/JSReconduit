import * as fs from "fs";
import * as path from "path";
import { ensureDir } from "./utils";

const SNIPPET = `// JSReconduit instrumentation snippet (paste in browser console)
(() => {
  const safeLog = (...args) => {
    try { console.log("[JSReconduit]", ...args); } catch (e) {}
  };

  const originalFetch = window.fetch;
  if (originalFetch) {
    window.fetch = async (...args) => {
      safeLog("fetch", args[0], args[1] || {});
      return originalFetch.apply(window, args);
    };
  }

  const OriginalXHR = window.XMLHttpRequest;
  if (OriginalXHR) {
    const open = OriginalXHR.prototype.open;
    const send = OriginalXHR.prototype.send;
    OriginalXHR.prototype.open = function(method, url) {
      this.__jsr_url = url;
      this.__jsr_method = method;
      return open.apply(this, arguments);
    };
    OriginalXHR.prototype.send = function(body) {
      safeLog("xhr", this.__jsr_method, this.__jsr_url, body || null);
      return send.apply(this, arguments);
    };
  }

  const OriginalWS = window.WebSocket;
  if (OriginalWS) {
    window.WebSocket = function(url, protocols) {
      safeLog("websocket", url, protocols || null);
      return new OriginalWS(url, protocols);
    };
    window.WebSocket.prototype = OriginalWS.prototype;
  }

  const sinkLog = (name, value) => safeLog("sink", name, value);
  const patchSink = (obj, prop) => {
    const desc = Object.getOwnPropertyDescriptor(obj, prop);
    if (!desc || !desc.set) {
      return;
    }
    Object.defineProperty(obj, prop, {
      set(value) {
        sinkLog(prop, value);
        return desc.set.call(this, value);
      },
      get() {
        return desc.get.call(this);
      },
      configurable: true,
    });
  };

  try {
    patchSink(Element.prototype, "innerHTML");
    patchSink(Element.prototype, "outerHTML");
  } catch (e) {}

  safeLog("Instrumentation active");
})();
`;

export async function writeInstrumentationSnippet(baseDir: string): Promise<string> {
  const outDir = path.join(baseDir, "instrumentation");
  await ensureDir(outDir);
  const outPath = path.join(outDir, "jsreconduit-snippet.js");
  await fs.promises.writeFile(outPath, SNIPPET, "utf8");
  return outPath;
}

