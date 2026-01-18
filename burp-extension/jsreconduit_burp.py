# JSReconduit Burp Suite Extension
# Passive JavaScript capture for Burp + VSCode workflows.

from burp import IBurpExtender, IHttpListener, ITab
import base64
import hashlib
import json
import os
import threading
import time
import traceback
import re
from java.awt import BorderLayout, GridBagConstraints, GridBagLayout, Insets
from javax.swing import (
    BoxLayout,
    JButton,
    JCheckBox,
    JLabel,
    JPanel,
    JScrollPane,
    JTextArea,
    JTextField,
    JTabbedPane,
    SwingUtilities,
)
try:
    from Queue import Queue, Full
except Exception:
    from queue import Queue, Full

try:
    import jsbeautifier
except Exception:
    jsbeautifier = None


class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("JSReconduit Capture")
        self.callbacks.registerHttpListener(self)

        self._log_buffer = []
        self.log_area = None
        self.config_path = os.path.expanduser("~/.jsreconduit/config.json")

        base_dir = os.getenv("JSRECONDUIT_BASE_DIR", "~/burp-js-capture")
        self._set_base_dir(base_dir)
        self.debug = os.getenv("JSRECONDUIT_DEBUG", "").lower() in ["1", "true", "yes"]
        self.beautify_enabled = jsbeautifier is not None
        self.async_enabled = os.getenv("JSRECONDUIT_ASYNC", "1").lower() in ["1", "true", "yes"]
        self.queue_max = int(os.getenv("JSRECONDUIT_QUEUE_MAX", "200"))
        self.heuristic_bytes = int(os.getenv("JSRECONDUIT_HEURISTIC_BYTES", "8192"))
        self.pretty_index = os.getenv("JSRECONDUIT_PRETTY_INDEX", "").lower() in ["1", "true", "yes"]
        self.enable_sourcemap = os.getenv("JSRECONDUIT_ENABLE_SOURCEMAP", "1").lower() in ["1", "true", "yes"]
        self.always_beautify = os.getenv("JSRECONDUIT_ALWAYS_BEAUTIFY", "").lower() in ["1", "true", "yes"]
        self.only_in_scope = os.getenv("JSRECONDUIT_ONLY_IN_SCOPE", "").lower() in ["1", "true", "yes"]
        disable_beautify = os.getenv("JSRECONDUIT_DISABLE_BEAUTIFY", "").lower() in ["1", "true", "yes"]
        if disable_beautify:
            self.beautify_enabled = False

        self._ensure_dirs()
        self._lock = threading.Lock()
        self._index_cache = None
        self._index_by_hash = {}
        self.queue = None
        self.worker = None

        config = self._load_config_from_file()
        self._apply_config(config, log=False)

        self._build_ui()
        self.callbacks.addSuiteTab(self)

        self._log("JSReconduit initialized. Base dir: %s" % self.base_dir)
        if jsbeautifier is None:
            self._log("JSReconduit: jsbeautifier not available; beautified output disabled.", is_error=True)
        self._ensure_worker()

    def _ensure_dirs(self):
        for path in [self.base_dir, self.raw_dir, self.beautified_dir, self.sourcemaps_dir, self.resolved_dir]:
            if not os.path.isdir(path):
                os.makedirs(path)

    def _set_base_dir(self, base_dir):
        self.base_dir = os.path.expanduser(base_dir)
        self.raw_dir = os.path.join(self.base_dir, "raw")
        self.beautified_dir = os.path.join(self.base_dir, "beautified")
        self.sourcemaps_dir = os.path.join(self.base_dir, "sourcemaps")
        self.resolved_dir = os.path.join(self.base_dir, "resolved")
        self.index_path = os.path.join(self.base_dir, "index.json")
        self._index_cache = None
        self._index_by_hash = {}

    def _ensure_worker(self):
        if not self.async_enabled:
            return
        if self.queue is None or getattr(self.queue, "maxsize", 0) != self.queue_max:
            self.queue = Queue(self.queue_max)
        if self.worker is None or not self.worker.isAlive():
            self.worker = threading.Thread(target=self._worker_loop)
            self.worker.setDaemon(True)
            self.worker.start()
            self._log("JSReconduit: async capture enabled (queue max %d)" % self.queue_max)

    def _build_ui(self):
        self.log_area = JTextArea()
        self.log_area.setEditable(False)
        self.log_area.setLineWrap(True)
        self.log_area.setWrapStyleWord(True)
        log_scroll = JScrollPane(self.log_area)

        settings_panel = JPanel()
        settings_panel.setLayout(GridBagLayout())
        constraints = GridBagConstraints()
        constraints.insets = Insets(4, 4, 4, 4)
        constraints.fill = GridBagConstraints.HORIZONTAL

        row = [0]
        def add_row(label_text, component):
            constraints.gridx = 0
            constraints.gridy = row[0]
            constraints.weightx = 0.0
            settings_panel.add(JLabel(label_text), constraints)
            constraints.gridx = 1
            constraints.weightx = 1.0
            settings_panel.add(component, constraints)
            row[0] += 1

        self.ui_base_dir_field = JTextField(self.base_dir, 40)
        add_row("Base directory", self.ui_base_dir_field)

        self.ui_async_checkbox = JCheckBox("Enable async capture", self.async_enabled)
        add_row("", self.ui_async_checkbox)

        self.ui_queue_field = JTextField(str(self.queue_max), 10)
        add_row("Queue max", self.ui_queue_field)

        self.ui_heuristic_field = JTextField(str(self.heuristic_bytes), 10)
        add_row("Heuristic bytes", self.ui_heuristic_field)

        self.ui_scope_checkbox = JCheckBox("Only capture in-scope", self.only_in_scope)
        add_row("", self.ui_scope_checkbox)

        self.ui_sourcemap_checkbox = JCheckBox("Enable sourcemap handling", self.enable_sourcemap)
        add_row("", self.ui_sourcemap_checkbox)

        self.ui_disable_beautify_checkbox = JCheckBox("Disable beautify", not self.beautify_enabled)
        add_row("", self.ui_disable_beautify_checkbox)

        self.ui_always_beautify_checkbox = JCheckBox("Always beautify", self.always_beautify)
        add_row("", self.ui_always_beautify_checkbox)

        self.ui_pretty_checkbox = JCheckBox("Pretty index JSON", self.pretty_index)
        add_row("", self.ui_pretty_checkbox)

        self.ui_debug_checkbox = JCheckBox("Debug logging", self.debug)
        add_row("", self.ui_debug_checkbox)

        button_panel = JPanel()
        button_panel.setLayout(BoxLayout(button_panel, BoxLayout.X_AXIS))
        apply_button = JButton("Apply Settings", actionPerformed=self._on_apply_settings)
        save_button = JButton("Save Settings", actionPerformed=self._on_save_settings)
        button_panel.add(apply_button)
        button_panel.add(save_button)
        add_row(" ", button_panel)

        tabs = JTabbedPane()
        tabs.addTab("Settings", settings_panel)
        tabs.addTab("Logs", log_scroll)

        self.main_panel = JPanel(BorderLayout())
        self.main_panel.add(tabs, BorderLayout.CENTER)
        self._flush_log_buffer()

    def _flush_log_buffer(self):
        if self.log_area is None:
            return
        for message in self._log_buffer:
            self.log_area.append(message + "\n")
        self._log_buffer = []

    def _log(self, message, is_error=False, to_output=True):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        formatted = "[%s] %s" % (timestamp, message)
        if to_output:
            if is_error:
                self.callbacks.printError(formatted)
            else:
                self.callbacks.printOutput(formatted)

        if self.log_area is None:
            self._log_buffer.append(formatted)
            return

        def append():
            self.log_area.append(formatted + "\n")
            try:
                self.log_area.setCaretPosition(self.log_area.getDocument().getLength())
            except Exception:
                pass

        SwingUtilities.invokeLater(append)

    def _load_config_from_file(self):
        if not self.config_path:
            return {}
        if not os.path.exists(self.config_path):
            return {}
        try:
            with open(self.config_path, "r") as handle:
                data = json.load(handle)
            if not isinstance(data, dict):
                return {}
            return data
        except Exception:
            return {}

    def _save_config_to_file(self, config):
        try:
            config_dir = os.path.dirname(self.config_path)
            if config_dir and not os.path.isdir(config_dir):
                os.makedirs(config_dir)
            with open(self.config_path, "w") as handle:
                json.dump(config, handle, indent=2, sort_keys=True)
            self._log("Settings saved to %s" % self.config_path)
        except Exception as exc:
            self._log("Failed to save settings: %s" % str(exc), is_error=True)

    def _apply_config(self, config, log=True):
        if config is None:
            config = {}
        base_dir = config.get("base_dir", self.base_dir)
        if base_dir and base_dir != self.base_dir:
            self._set_base_dir(base_dir)

        self.async_enabled = bool(config.get("async_enabled", self.async_enabled))
        self.queue_max = int(config.get("queue_max", self.queue_max))
        self.heuristic_bytes = int(config.get("heuristic_bytes", self.heuristic_bytes))
        self.pretty_index = bool(config.get("pretty_index", self.pretty_index))
        self.enable_sourcemap = bool(config.get("enable_sourcemap", self.enable_sourcemap))
        self.always_beautify = bool(config.get("always_beautify", self.always_beautify))
        self.debug = bool(config.get("debug", self.debug))
        self.only_in_scope = bool(config.get("only_in_scope", self.only_in_scope))

        disable_beautify = bool(config.get("disable_beautify", False))
        if disable_beautify or jsbeautifier is None:
            self.beautify_enabled = False
            self.always_beautify = False
        else:
            self.beautify_enabled = True

        self._ensure_dirs()
        self._ensure_worker()
        if log:
            self._log("Settings updated.")

    def _read_ui_config(self):
        config = {}
        base_dir = self.ui_base_dir_field.getText().strip()
        if base_dir:
            config["base_dir"] = base_dir
        config["async_enabled"] = self.ui_async_checkbox.isSelected()
        config["queue_max"] = self._parse_int(self.ui_queue_field.getText(), self.queue_max)
        config["heuristic_bytes"] = self._parse_int(self.ui_heuristic_field.getText(), self.heuristic_bytes)
        config["only_in_scope"] = self.ui_scope_checkbox.isSelected()
        config["enable_sourcemap"] = self.ui_sourcemap_checkbox.isSelected()
        config["disable_beautify"] = self.ui_disable_beautify_checkbox.isSelected()
        config["always_beautify"] = self.ui_always_beautify_checkbox.isSelected()
        config["pretty_index"] = self.ui_pretty_checkbox.isSelected()
        config["debug"] = self.ui_debug_checkbox.isSelected()
        return config

    def _parse_int(self, value, fallback):
        try:
            return int(value)
        except Exception:
            self._log("Invalid number: %s" % value, is_error=True)
            return fallback

    def _sync_ui_from_config(self):
        if not hasattr(self, "ui_base_dir_field"):
            return
        self.ui_base_dir_field.setText(self.base_dir)
        self.ui_async_checkbox.setSelected(self.async_enabled)
        self.ui_queue_field.setText(str(self.queue_max))
        self.ui_heuristic_field.setText(str(self.heuristic_bytes))
        self.ui_scope_checkbox.setSelected(self.only_in_scope)
        self.ui_sourcemap_checkbox.setSelected(self.enable_sourcemap)
        self.ui_disable_beautify_checkbox.setSelected(not self.beautify_enabled)
        self.ui_always_beautify_checkbox.setSelected(self.always_beautify)
        self.ui_pretty_checkbox.setSelected(self.pretty_index)
        self.ui_debug_checkbox.setSelected(self.debug)

    def _on_apply_settings(self, event):
        config = self._read_ui_config()
        self._apply_config(config, log=True)
        self._sync_ui_from_config()

    def _on_save_settings(self, event):
        config = self._read_ui_config()
        self._apply_config(config, log=True)
        self._save_config_to_file(config)
        self._sync_ui_from_config()

    def getTabCaption(self):
        return "JSReconduit"

    def getUiComponent(self):
        return self.main_panel

    def _load_index_cache(self):
        if self._index_cache is not None:
            return
        data = []
        if os.path.exists(self.index_path):
            try:
                with open(self.index_path, "r") as handle:
                    data = json.load(handle)
                if not isinstance(data, list):
                    data = []
            except Exception:
                data = []
        self._index_cache = data
        self._index_by_hash = {}
        for entry in data:
            sha = entry.get("sha256")
            if sha:
                self._index_by_hash[sha] = entry

    def _enqueue_capture(self, job):
        if self.queue is None:
            self._process_capture(job)
            return
        try:
            self.queue.put_nowait(job)
        except Full:
            self._log("JSReconduit: capture queue full, dropping %s" % job.get("url"), is_error=True)

    def _worker_loop(self):
        while True:
            job = self.queue.get()
            try:
                self._process_capture(job)
            except Exception as exc:
                self._log("JSReconduit worker error: %s" % str(exc), is_error=True)
                self._log(traceback.format_exc(), is_error=True)
            finally:
                try:
                    self.queue.task_done()
                except Exception:
                    pass

    def _process_capture(self, job):
        url = job.get("url")
        method = job.get("method")
        status_code = job.get("status_code")
        content_type = job.get("content_type")
        referer = job.get("referer") or ""
        host = job.get("host") or ""
        path = job.get("path") or ""
        body_bytes = self._coerce_bytes(job.get("body_bytes"))
        body_hash = self._sha256(body_bytes)

        with self._lock:
            self._load_index_cache()
            existing = self._index_by_hash.get(body_hash)
            if existing:
                self._update_observations(existing, str(url), method, status_code, content_type, referer, host, path)
                self._write_index_cache()
                if self.debug:
                    self._log("JSReconduit: deduped %s" % url, to_output=True)
                else:
                    self._log("Deduped %s" % url, to_output=False)
                return

        raw_name = self._build_base_name(body_hash, url, method)
        raw_path = self._write_file(self.raw_dir, raw_name, ".js", body_bytes)
        if self.debug:
            self._log("JSReconduit: wrote raw %s" % raw_path, to_output=True)
        else:
            self._log("Captured %s" % raw_path, to_output=False)

        body_text = None
        if self.beautify_enabled or self.enable_sourcemap:
            body_text = self.helpers.bytesToString(body_bytes)

        beautified_path = None
        if self.beautify_enabled and body_text:
            if self.always_beautify or self._is_minified(body_text):
                beautified = self._beautify_js(body_text)
                if beautified:
                    beautified_path = self._write_file(
                        self.beautified_dir,
                        raw_name,
                        ".js",
                        beautified.encode("utf-8"),
                    )

        sourcemap_ref = ""
        sourcemap_path = ""
        if self.enable_sourcemap and body_text:
            sourcemap_ref, sourcemap_path = self._handle_sourcemap(body_text, str(url), raw_name)

        entry = {
            "url": str(url),
            "method": method,
            "status_code": status_code,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "content_type": content_type,
            "referer": referer,
            "host": host,
            "path": path,
            "original_filename": self._infer_filename(url),
            "sha256": body_hash,
            "sourcemap_ref": sourcemap_ref,
            "raw_path": raw_path,
            "beautified_path": beautified_path,
            "sourcemap_path": sourcemap_path,
            "resolved_dir": self.resolved_dir,
        }

        self._append_index(entry)
        if self.debug:
            self._log("JSReconduit: indexed %s" % raw_path, to_output=True)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        try:
            response = messageInfo.getResponse()
            if response is None:
                return

            response_info = self.helpers.analyzeResponse(response)
            headers = response_info.getHeaders()
            status_code = response_info.getStatusCode()
            body_offset = response_info.getBodyOffset()
            body_bytes = response[body_offset:]

            request_info = self.helpers.analyzeRequest(messageInfo)
            url = request_info.getUrl()
            method = request_info.getMethod()
            request_headers = request_info.getHeaders()
            referer = self._get_header(request_headers, "Referer") or self._get_header(request_headers, "Referrer")
            host = ""
            path = ""
            try:
                host = url.getHost() or ""
                path = url.getPath() or ""
            except Exception:
                pass

            content_type = self._get_header(headers, "Content-Type")
            if self.debug:
                self._log("JSReconduit: saw %s %s (%s)" % (method, url, content_type), to_output=True)

            if self.only_in_scope:
                in_scope = False
                try:
                    in_scope = self.callbacks.isInScope(url)
                except Exception:
                    in_scope = False
                if not in_scope:
                    if self.debug:
                        self._log("JSReconduit: skip %s (out of scope)" % url, to_output=True)
                    return

            should_capture = False
            if content_type and "javascript" in content_type.lower():
                should_capture = True
            else:
                try:
                    path = url.getPath()
                    if path and (path.lower().endswith(".js") or path.lower().endswith(".mjs")):
                        should_capture = True
                except Exception:
                    pass

            if not should_capture:
                sample_end = min(len(response), body_offset + self.heuristic_bytes)
                sample_bytes = response[body_offset:sample_end]
                sample_text = self.helpers.bytesToString(sample_bytes)
                if self._looks_like_js(sample_text):
                    should_capture = True

            if not should_capture:
                if self.debug:
                    self._log("JSReconduit: skip %s (not JS)" % url, to_output=True)
                return

            job = {
                "url": url,
                "method": method,
                "status_code": status_code,
                "content_type": content_type,
                "body_bytes": body_bytes,
                "referer": referer,
                "host": host,
                "path": path,
            }

            if self.async_enabled:
                self._enqueue_capture(job)
            else:
                self._process_capture(job)

        except Exception as exc:
            self._log("JSReconduit error: %s" % str(exc), is_error=True)
            self._log(traceback.format_exc(), is_error=True)

    def _get_header(self, headers, name):
        prefix = name.lower() + ":"
        for header in headers:
            if header.lower().startswith(prefix):
                return header.split(":", 1)[1].strip()
        return ""

    def _is_javascript(self, content_type, url, body_text):
        if content_type and "javascript" in content_type.lower():
            return True
        try:
            path = url.getPath()
            if path and path.lower().endswith(".js"):
                return True
        except Exception:
            pass

        return self._looks_like_js(body_text)

    def _looks_like_js(self, body_text):
        sample = body_text[:10000]
        if not sample:
            return False
        keywords = ["function", "=>", "var ", "let ", "const ", "import ", "export ", "require(", "define("]
        score = 0
        for kw in keywords:
            if kw in sample:
                score += 1
        if score >= 2:
            return True
        if "{" in sample and "}" in sample and ";" in sample:
            return True
        return False

    def _is_minified(self, body_text):
        lines = body_text.splitlines()
        if not lines:
            return False
        long_lines = [l for l in lines if len(l) > 200]
        whitespace = sum(1 for c in body_text if c in " \t\n\r")
        ratio = float(whitespace) / float(max(1, len(body_text)))
        return len(long_lines) >= 1 and ratio < 0.2

    def _beautify_js(self, body_text):
        if not self.beautify_enabled:
            return None
        try:
            opts = jsbeautifier.default_options()
            opts.indent_size = 2
            opts.preserve_newlines = True
            return jsbeautifier.beautify(body_text, opts)
        except Exception as exc:
            self._log("JSReconduit beautify error: %s" % str(exc), is_error=True)
            if "No module named" in str(exc):
                self.beautify_enabled = False
                self._log("JSReconduit: disabling beautifier due to missing dependency.", is_error=True)
            return None

    def _sha256(self, body_bytes):
        return hashlib.sha256(self._coerce_bytes(body_bytes)).hexdigest()

    def _build_base_name(self, body_hash, url, method):
        slug = self._slugify_url(url, method)
        if slug:
            return "%s__%s" % (body_hash, slug)
        return body_hash

    def _slugify_url(self, url, method):
        try:
            host = url.getHost() or ""
            path = url.getPath() or ""
        except Exception:
            host = ""
            path = ""
        raw = "%s_%s_%s" % (method, host, path.strip("/"))
        raw = raw.replace("..", "_")
        slug = re.sub(r"[^A-Za-z0-9._-]+", "_", raw)
        slug = slug.strip("_")
        if len(slug) > 80:
            slug = slug[:80]
        return slug

    def _write_file(self, directory, base_name, ext, data_bytes):
        path = self._unique_path(directory, base_name, ext)
        with open(path, "wb") as handle:
            handle.write(self._coerce_bytes(data_bytes))
        return path

    def _coerce_bytes(self, data):
        if data is None:
            return ""
        try:
            if isinstance(data, unicode):
                return data.encode("utf-8")
        except Exception:
            pass
        try:
            if isinstance(data, str):
                return data
        except Exception:
            pass
        try:
            if hasattr(data, "tostring"):
                return data.tostring()
        except Exception:
            pass
        try:
            if hasattr(self, "helpers"):
                return self.helpers.bytesToString(data)
        except Exception:
            pass
        try:
            return "".join([chr(b) for b in data])
        except Exception:
            pass
        try:
            return str(data)
        except Exception:
            return ""

    def _unique_path(self, directory, base_name, ext):
        candidate = os.path.join(directory, base_name + ext)
        if not os.path.exists(candidate):
            return candidate
        idx = 1
        while True:
            candidate = os.path.join(directory, "%s-%d%s" % (base_name, idx, ext))
            if not os.path.exists(candidate):
                return candidate
            idx += 1

    def _infer_filename(self, url):
        try:
            path = url.getPath()
            if not path:
                return ""
            name = path.split("/")[-1]
            return name
        except Exception:
            return ""

    def _extract_sourcemap_url(self, body_text):
        marker = "sourceMappingURL="
        idx = body_text.rfind(marker)
        if idx == -1:
            return ""
        tail = body_text[idx + len(marker):]
        for sep in ["\n", "\r"]:
            if sep in tail:
                tail = tail.split(sep, 1)[0]
        tail = tail.replace("*/", "").strip()
        return tail

    def _handle_sourcemap(self, body_text, url, base_name):
        ref = self._extract_sourcemap_url(body_text)
        if not ref:
            return "", ""

        if ref.startswith("data:application/json;base64,"):
            encoded = ref.split(",", 1)[1]
            try:
                data = base64.b64decode(encoded)
                sm_path = self._write_file(self.sourcemaps_dir, base_name, ".map", data)
                return ref, sm_path
            except Exception as exc:
                self._log("JSReconduit sourcemap decode error: %s" % str(exc), is_error=True)
                return ref, ""

        return ref, ""

    def _append_index(self, entry):
        with self._lock:
            self._load_index_cache()
            data = list(self._index_cache or [])
            entry = self._coerce_entry(entry)
            entry["first_seen"] = entry.get("timestamp")
            entry["last_seen"] = entry.get("timestamp")
            entry["seen_count"] = 1
            entry["observations"] = [
                {
                    "url": entry.get("url"),
                    "method": entry.get("method"),
                    "referer": entry.get("referer"),
                    "first_seen": entry.get("timestamp"),
                    "last_seen": entry.get("timestamp"),
                    "count": 1,
                    "status_code": entry.get("status_code"),
                    "content_type": entry.get("content_type"),
                }
            ]

            data.append(entry)
            self._index_cache = data
            sha = entry.get("sha256")
            if sha:
                self._index_by_hash[sha] = entry
            self._write_index_cache()

    def _write_index_cache(self):
        data = list(self._index_cache or [])
        tmp_path = self.index_path + ".tmp"
        try:
            with open(tmp_path, "w") as handle:
                if self.pretty_index:
                    json.dump(data, handle, indent=2, sort_keys=True)
                else:
                    json.dump(data, handle)
            os.rename(tmp_path, self.index_path)
        except Exception as exc:
            self._log("JSReconduit index write error: %s" % str(exc), is_error=True)
            self._log(traceback.format_exc(), is_error=True)
            try:
                jsonl_path = self.index_path + ".jsonl"
                if data:
                    with open(jsonl_path, "a") as handle:
                        handle.write(json.dumps(self._coerce_entry(data[-1])) + "\\n")
            except Exception:
                pass

    def _update_observations(self, entry, url, method, status_code, content_type, referer, host, path):
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        entry["last_seen"] = timestamp
        entry["seen_count"] = int(entry.get("seen_count", 0)) + 1
        entry["status_code"] = status_code
        entry["content_type"] = content_type
        entry["referer"] = referer or entry.get("referer")
        entry["host"] = host or entry.get("host")
        entry["path"] = path or entry.get("path")

        observations = entry.get("observations")
        if observations is None or not isinstance(observations, list):
            observations = []
            entry["observations"] = observations

        key = "%s|%s|%s" % (method, url, referer or "")
        for obs in observations:
            if obs.get("key") == key:
                obs["last_seen"] = timestamp
                obs["count"] = int(obs.get("count", 0)) + 1
                obs["status_code"] = status_code
                obs["content_type"] = content_type
                obs["referer"] = referer
                return

        observations.append(
            {
                "key": key,
                "url": url,
                "method": method,
                "referer": referer,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "count": 1,
                "status_code": status_code,
                "content_type": content_type,
            }
        )

    def _coerce_entry(self, entry):
        coerced = {}
        for key in entry:
            coerced[key] = self._safe_value(entry[key])
        return coerced

    def _safe_value(self, value):
        try:
            long_type = long
        except Exception:
            long_type = int
        if value is None:
            return None
        if isinstance(value, (bool, int, long_type, float)):
            return value
        try:
            if isinstance(value, unicode):
                return value
        except Exception:
            pass
        try:
            if isinstance(value, str):
                return value
        except Exception:
            pass
        try:
            return str(value)
        except Exception:
            return repr(value)
