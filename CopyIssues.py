# pylint: disable=import-error
from burp import IBurpExtender, ITab, IExtensionStateListener, IScannerListener
from javax.swing import JPanel, JButton, JList, JScrollPane, DefaultListModel, JOptionPane, BorderFactory, ListCellRenderer, JLabel, JCheckBox, BoxLayout, Box, JTextField, JComboBox, Timer, SwingUtilities
from java.awt import BorderLayout, GridLayout, Toolkit, Color, Font, FlowLayout, Component
from javax.swing.event import DocumentListener
from java.awt.datatransfer import StringSelection
from java.awt.event import MouseAdapter, ActionListener
from java.io import File, FileWriter, FileReader, BufferedReader
from java.lang import Runnable
from java.text import SimpleDateFormat
from java.util import Date
import hashlib
import json
import re
import threading
import time

class BurpExtender(IBurpExtender, ITab, IExtensionStateListener, IScannerListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("CopyIssues")
        self._scanner_listener_registered = False
        
        self.issues_cache = {}
        self.all_issues_data = []
        self.issue_status = self._load_status()
        self.copied_issue_keys = set()
        self.duplicate_issue_keys = set()
        self.displayed_rows = []
        self.group_by_host = False
        self.list_model = DefaultListModel()
        self.issue_list = JList(self.list_model)
        self.issue_list.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.issue_list.setCellRenderer(AlternatingRowRenderer(self))
        self.issue_list.addMouseListener(DoubleClickListener(self))
        self.current_filter = {"severity": None, "confidence": None}
        self.filter_buttons = {}
        self._cache_lock = threading.RLock()
        self._cache_ttl_seconds = 5
        self._issue_cache_timestamp = 0
        self._issues_by_filter = {}
        self._count_cache = {}
        self._last_rendered_counts = {}
        self._count_refresh_running = False
        self._count_refresh_pending = False
        self._load_request_id = 0
        self._last_scanner_refresh_request = 0
        self._scanner_refresh_min_interval = 2
        self._export_lock = threading.RLock()
        self._export_running = False
        self._export_cancel_requested = False
        
        self._panel = JPanel(BorderLayout())
        self._panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        center_panel = JPanel(BorderLayout())
        
        search_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        search_panel.add(JLabel("Search:"))
        self.search_field = JTextField(30)
        self.search_field.getDocument().addDocumentListener(SearchListener(self))
        search_panel.add(self.search_field)
        search_panel.add(JLabel("Sort:"))
        self.sort_combo = JComboBox(["Default", "Host", "Issue Type", "URL"])
        self.sort_combo.addActionListener(lambda e: self._apply_filters())
        search_panel.add(self.sort_combo)
        self.group_btn = JButton("Group by Host")
        self.group_btn.addActionListener(lambda e: self._toggle_grouping())
        search_panel.add(self.group_btn)
        center_panel.add(search_panel, BorderLayout.NORTH)
        
        list_scroll = JScrollPane(self.issue_list)
        list_scroll.setBorder(BorderFactory.createTitledBorder("Scan Issues (Double-click to copy)"))
        center_panel.add(list_scroll, BorderLayout.CENTER)
        
        status_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.tested_cb = JCheckBox("Tested")
        self.exploited_cb = JCheckBox("Exploited")
        self.fp_cb = JCheckBox("False Positive")
        self.tested_cb.addActionListener(lambda e: self._update_status())
        self.exploited_cb.addActionListener(lambda e: self._update_status())
        self.fp_cb.addActionListener(lambda e: self._update_status())
        clear_btn = JButton("Clear")
        clear_btn.addActionListener(lambda e: self._clear_status())
        status_panel.add(self.tested_cb)
        status_panel.add(self.exploited_cb)
        status_panel.add(self.fp_cb)
        status_panel.add(clear_btn)
        center_panel.add(status_panel, BorderLayout.SOUTH)
        
        self._panel.add(center_panel, BorderLayout.CENTER)
        self.issue_list.addListSelectionListener(lambda e: self._on_selection_change() if not e.getValueIsAdjusting() else None)
        
        btn_panel = JPanel(GridLayout(3, 3, 5, 5))
        btn_panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0))
        
        high_certain = JButton("High - Certain")
        high_certain.setBackground(Color(220, 53, 69))
        high_certain.setForeground(Color.WHITE)
        high_certain.addActionListener(lambda e: self.load_issues("High", "Certain"))
        self.filter_buttons[("High", "Certain")] = high_certain
        
        high_firm = JButton("High - Firm")
        high_firm.setBackground(Color(255, 120, 130))
        high_firm.setForeground(Color.WHITE)
        high_firm.addActionListener(lambda e: self.load_issues("High", "Firm"))
        self.filter_buttons[("High", "Firm")] = high_firm
        
        high_tentative = JButton("High - Tentative")
        high_tentative.setBackground(Color(255, 180, 185))
        high_tentative.addActionListener(lambda e: self.load_issues("High", "Tentative"))
        self.filter_buttons[("High", "Tentative")] = high_tentative
        
        med_certain = JButton("Medium - Certain")
        med_certain.setBackground(Color(255, 193, 7))
        med_certain.addActionListener(lambda e: self.load_issues("Medium", "Certain"))
        self.filter_buttons[("Medium", "Certain")] = med_certain
        
        med_firm = JButton("Medium - Firm")
        med_firm.setBackground(Color(255, 215, 100))
        med_firm.addActionListener(lambda e: self.load_issues("Medium", "Firm"))
        self.filter_buttons[("Medium", "Firm")] = med_firm
        
        med_tentative = JButton("Medium - Tentative")
        med_tentative.setBackground(Color(255, 235, 170))
        med_tentative.addActionListener(lambda e: self.load_issues("Medium", "Tentative"))
        self.filter_buttons[("Medium", "Tentative")] = med_tentative
        
        self.export_btn = JButton("Export All")
        self.export_btn.setBackground(Color(40, 167, 69))
        self.export_btn.setForeground(Color.WHITE)
        self.export_btn.addActionListener(lambda e: self.export_all())

        self.cancel_export_btn = JButton("Cancel Export")
        self.cancel_export_btn.setBackground(Color(220, 53, 69))
        self.cancel_export_btn.setForeground(Color.WHITE)
        self.cancel_export_btn.setEnabled(False)
        self.cancel_export_btn.addActionListener(lambda e: self._cancel_export())
        
        refresh_btn = JButton("Refresh")
        refresh_btn.setBackground(Color(108, 117, 125))
        refresh_btn.setForeground(Color.WHITE)
        refresh_btn.addActionListener(lambda e: self.refresh_current())
        
        btn_panel.add(high_certain)
        btn_panel.add(high_firm)
        btn_panel.add(high_tentative)
        btn_panel.add(med_certain)
        btn_panel.add(med_firm)
        btn_panel.add(med_tentative)
        btn_panel.add(self.export_btn)
        btn_panel.add(refresh_btn)
        btn_panel.add(self.cancel_export_btn)

        self.export_status_label = JLabel("")
        self.export_status_label.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._panel.add(self.export_status_label, BorderLayout.SOUTH)
        
        self._panel.add(btn_panel, BorderLayout.NORTH)
        callbacks.addSuiteTab(self)
        callbacks.registerExtensionStateListener(self)
        try:
            callbacks.registerScannerListener(self)
            self._scanner_listener_registered = True
        except Exception as e:
            self._callbacks.printError("Scanner listener registration failed: " + str(e))
        
        # Start with zeroed counters and refresh asynchronously.
        self._apply_button_counts({})
        
        # Refresh counters periodically without blocking the UI thread.
        self.timer = Timer(15000, UpdateCountsListener(self))
        self.timer.setInitialDelay(5000)
        self.timer.start()
        self._request_count_refresh(force=True)

    def getTabCaption(self):
        count = self.list_model.getSize()
        return "CopyIssues" if count == 0 else "CopyIssues ({})".format(count)
    
    def getUiComponent(self):
        return self._panel

    def extensionUnloaded(self):
        if hasattr(self, "timer") and self.timer:
            self.timer.stop()
        if self._scanner_listener_registered:
            try:
                self._callbacks.removeScannerListener(self)
            except Exception as e:
                self._callbacks.printError("Scanner listener cleanup failed: " + str(e))
        self._cancel_export()

    def newScanIssue(self, issue):
        self._invalidate_issue_cache()
        now = time.time()
        should_refresh = False
        with self._cache_lock:
            if now - self._last_scanner_refresh_request >= self._scanner_refresh_min_interval:
                self._last_scanner_refresh_request = now
                should_refresh = True

        if should_refresh:
            self._request_count_refresh(force=True)

    def _invalidate_issue_cache(self):
        with self._cache_lock:
            self._issue_cache_timestamp = 0
            self._issues_by_filter = {}
            self._count_cache = {}
    
    def refresh_current(self):
        self._request_count_refresh(force=True)
        if self.current_filter["severity"] and self.current_filter["confidence"]:
            self.copied_issue_keys.clear()
            self.load_issues(self.current_filter["severity"], self.current_filter["confidence"])
        else:
            JOptionPane.showMessageDialog(self._panel, "Counts refreshed! Click a filter to view issues.", "Refreshed", JOptionPane.INFORMATION_MESSAGE)

    def _run_on_ui(self, fn):
        SwingUtilities.invokeLater(UiRunnable(fn))

    def _build_issue_groups(self, all_issues):
        grouped = {}
        counts = {}
        for issue in all_issues:
            sev = issue.getSeverity()
            conf = issue.getConfidence()
            if sev not in ["High", "Medium"]:
                continue

            key = (sev, conf)
            counts[key] = counts.get(key, 0) + 1
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(issue)

        return grouped, counts

    def _refresh_issue_cache(self, force=False):
        now = time.time()
        with self._cache_lock:
            cache_is_fresh = self._issues_by_filter and (now - self._issue_cache_timestamp) < self._cache_ttl_seconds
            if cache_is_fresh and not force:
                return self._issues_by_filter, self._count_cache

        all_issues = self._callbacks.getScanIssues(None) or []
        grouped, counts = self._build_issue_groups(all_issues)

        with self._cache_lock:
            self._issues_by_filter = grouped
            self._count_cache = counts
            self._issue_cache_timestamp = time.time()
            return self._issues_by_filter, self._count_cache

    def _request_count_refresh(self, force=False):
        with self._cache_lock:
            now = time.time()
            cache_is_fresh = self._issues_by_filter and (now - self._issue_cache_timestamp) < self._cache_ttl_seconds
            if cache_is_fresh and not force:
                counts_snapshot = dict(self._count_cache)
                self._run_on_ui(lambda: self._apply_button_counts(counts_snapshot))
                return

            if self._count_refresh_running:
                self._count_refresh_pending = True
                return

            self._count_refresh_running = True

        worker = threading.Thread(target=self._count_refresh_worker, args=(force,))
        worker.setDaemon(True)
        worker.start()

    def _count_refresh_worker(self, force):
        try:
            _, counts = self._refresh_issue_cache(force=force)
            counts_snapshot = dict(counts)
            self._run_on_ui(lambda: self._apply_button_counts(counts_snapshot))
        except Exception as e:
            self._callbacks.printError("Error refreshing issue counts: " + str(e))
        finally:
            with self._cache_lock:
                pending = self._count_refresh_pending
                self._count_refresh_pending = False
                self._count_refresh_running = False

            if pending:
                self._request_count_refresh(force=True)

    def _apply_button_counts(self, counts):
        if counts == self._last_rendered_counts:
            return

        for key, btn in self.filter_buttons.items():
            count = counts.get(key, 0)
            text = "{} - {} ({})".format(key[0], key[1], count)
            btn.setText(text)

        self._last_rendered_counts = dict(counts)

    def _update_button_counts(self):
        self._request_count_refresh(force=False)

    def load_issues(self, severity, confidence):
        self.current_filter = {"severity": severity, "confidence": confidence}
        self.copied_issue_keys.clear()
        self.all_issues_data = []
        self.issues_cache = {}
        self.duplicate_issue_keys = set()
        self.displayed_rows = []
        self.issue_list.clearSelection()
        self.list_model.clear()
        self.list_model.addElement("Loading {} {} issues...".format(severity, confidence))
        self._callbacks.setExtensionName("CopyIssues (loading...)")

        with self._cache_lock:
            self._load_request_id += 1
            load_request_id = self._load_request_id

        self._request_count_refresh(force=False)
        worker = threading.Thread(target=self._load_issues_worker, args=(severity, confidence, load_request_id))
        worker.setDaemon(True)
        worker.start()

    def _load_issues_worker(self, severity, confidence, load_request_id):
        try:
            issues_by_filter, _ = self._refresh_issue_cache(force=False)
            issues = list(issues_by_filter.get((severity, confidence), []))

            # If the selected bucket is empty, force one refresh to avoid stale cache misses.
            if not issues:
                issues_by_filter, _ = self._refresh_issue_cache(force=True)
                issues = list(issues_by_filter.get((severity, confidence), []))

            dup_counts = {}
            for issue in issues:
                http_messages = issue.getHttpMessages()
                if http_messages:
                    service = http_messages[0].getHttpService()
                    host = service.getHost() if service else ""
                    issue_name = issue.getIssueName()
                    dup_key = "{}:{}".format(host, issue_name)
                    dup_counts[dup_key] = dup_counts.get(dup_key, 0) + 1

            rows = []
            cache = {}
            duplicate_issue_keys = set()
            for idx, issue in enumerate(issues):
                try:
                    http_messages = issue.getHttpMessages()
                    service = http_messages[0].getHttpService() if http_messages else None
                    host = service.getHost() if service else ""
                    issue_name = issue.getIssueName()
                    issue_url = str(issue.getUrl())
                    issue_id = hashlib.md5("{}{}{}".format(host, issue_url, issue_name).encode('utf-8')).hexdigest()

                    key = "[{}] {} - {}".format(idx + 1, issue_name, issue_url)
                    dup_key = "{}:{}".format(host, issue_name)
                    if dup_counts.get(dup_key, 1) > 1:
                        duplicate_issue_keys.add(key)

                    cache[key] = {"prompt": None, "id": issue_id, "issue": issue}
                    rows.append({"key": key, "host": host, "issue_name": issue_name, "url": issue_url})
                except Exception as e:
                    self._callbacks.printError("Error processing issue: " + str(e))

            def apply_results():
                with self._cache_lock:
                    if load_request_id != self._load_request_id:
                        return

                self.all_issues_data = rows
                self.issues_cache = cache
                self.duplicate_issue_keys = duplicate_issue_keys

                if not rows:
                    self.displayed_rows = []
                    self.list_model.clear()
                    self._callbacks.printOutput("[!] No {} {} issues found".format(severity, confidence))
                else:
                    self._refresh_list_view()
                    self._callbacks.printOutput("[+] Loaded {} {} {} issues".format(len(rows), severity, confidence))

                self._callbacks.setExtensionName("CopyIssues ({})".format(len(rows)))

            self._run_on_ui(apply_results)
        except Exception as e:
            error_msg = str(e)
            self._callbacks.printError("Error loading issues: " + error_msg)

            def apply_error():
                with self._cache_lock:
                    if load_request_id != self._load_request_id:
                        return

                self.all_issues_data = []
                self.issues_cache = {}
                self.duplicate_issue_keys = set()
                self.displayed_rows = []
                self.list_model.clear()
                self.list_model.addElement("Failed to load issues. Check Extender output.")
                self._callbacks.setExtensionName("CopyIssues")

            self._run_on_ui(apply_error)

    def _build_issue_prompt(self, issue):
        if not issue:
            return None

        http_data = ""
        try:
            http_messages = issue.getHttpMessages()
            if http_messages and len(http_messages) > 0:
                req = self._helpers.bytesToString(http_messages[0].getRequest())
                lines = req.split('\r\n')
                method_line = lines[0] if lines else ""
                headers = '\r\n'.join([h for h in lines[1:] if ':' in h][:15])

                body = ""
                if '\r\n\r\n' in req:
                    body_content = req.split('\r\n\r\n', 1)[1][:500]
                    if body_content.strip():
                        body = "\nBody: {}\n".format(body_content)

                http_data = "\n=== HTTP REQUEST ===\n{}\n{}{}\n".format(method_line, headers, body)
        except Exception as e:
            self._callbacks.printError("Error extracting HTTP data: " + str(e))

        references = ""
        try:
            refs = issue.getReferences()
            if refs:
                references = "\n\nReferences:\n" + '\n'.join(['- ' + str(r) for r in refs[:3]])
        except Exception as e:
            self._callbacks.printError("Error extracting references: " + str(e))

        return """=== BURP SCAN FINDING ===
Severity: {} (Confidence: {})
Issue: {}
URL: {}

Description:
{}

Background:
{}

Remediation:
{}{}{}
""".format(issue.getSeverity(), issue.getConfidence(), issue.getIssueName(),
           str(issue.getUrl()), issue.getIssueDetail() or "No details",
           issue.getIssueBackground() or "N/A",
           issue.getRemediationDetail() or "N/A", references, http_data)
    
    def _apply_filters(self):
        self._refresh_list_view()

    def _set_display_rows(self, rows):
        self.displayed_rows = rows
        self.list_model.clear()
        for row in rows:
            self.list_model.addElement(row["text"])

    def _refresh_list_view(self):
        search_text = self.search_field.getText().lower()
        sort_by = self.sort_combo.getSelectedItem()

        filtered = [d for d in self.all_issues_data if search_text in d["key"].lower()]

        if sort_by == "Host":
            filtered.sort(key=lambda x: x["host"])
        elif sort_by == "Issue Type":
            filtered.sort(key=lambda x: x["issue_name"])
        elif sort_by == "URL":
            filtered.sort(key=lambda x: x["url"])

        rows = []
        if self.group_by_host:
            grouped = {}
            for d in filtered:
                host = d["host"] or "<no-host>"
                if host not in grouped:
                    grouped[host] = []
                grouped[host].append(d)

            for host in sorted(grouped.keys()):
                rows.append({
                    "type": "header",
                    "text": "=== {} ({}) ===".format(host, len(grouped[host])),
                    "issue_key": None
                })
                for item in grouped[host]:
                    rows.append({
                        "type": "issue",
                        "text": "  " + item["key"],
                        "issue_key": item["key"]
                    })
        else:
            for item in filtered:
                rows.append({
                    "type": "issue",
                    "text": item["key"],
                    "issue_key": item["key"]
                })

        self._set_display_rows(rows)
        self._callbacks.setExtensionName("CopyIssues ({})".format(len(filtered)))

    def _get_selected_issue_key(self):
        idx = self.issue_list.getSelectedIndex()
        if idx < 0 or idx >= len(self.displayed_rows):
            return None
        row = self.displayed_rows[idx]
        if row.get("type") != "issue":
            return None
        return row.get("issue_key")
    
    def _toggle_grouping(self):
        self.group_by_host = not self.group_by_host
        self.group_btn.setText("Ungroup" if self.group_by_host else "Group by Host")
        self._refresh_list_view()
    
    def _get_export_dir(self, subdir=""):
        import os
        base_paths = []
        if os.name == 'nt':
            base_paths.append("C:\\burp_exports")
        base_paths.append(os.path.join(os.path.expanduser("~"), "burp_exports"))
        
        for base in base_paths:
            path = os.path.join(base, subdir) if subdir else base
            try:
                File(path).mkdirs()
                return path
            except Exception as e:
                self._callbacks.printError("Error creating export dir: " + str(e))
                continue
        return None
    
    def export_all(self):
        with self._export_lock:
            if self._export_running:
                JOptionPane.showMessageDialog(self._panel, "Export already in progress.", "Info", JOptionPane.INFORMATION_MESSAGE)
                return
            self._export_running = True
            self._export_cancel_requested = False

        self._set_export_ui_state(True)
        self._set_export_status("Exporting issues...")
        worker = threading.Thread(target=self._export_all_worker)
        worker.setDaemon(True)
        worker.start()

    def _set_export_ui_state(self, running):
        self.export_btn.setEnabled(not running)
        self.cancel_export_btn.setEnabled(running)

    def _set_export_status(self, message):
        self.export_status_label.setText(message or "")

    def _cancel_export(self):
        with self._export_lock:
            if not self._export_running:
                return
            self._export_cancel_requested = True
        self._run_on_ui(lambda: self._set_export_status("Cancelling export..."))

    def _is_export_cancelled(self):
        with self._export_lock:
            return self._export_cancel_requested

    def _finish_export(self):
        with self._export_lock:
            self._export_running = False
            self._export_cancel_requested = False
        self._run_on_ui(lambda: self._set_export_ui_state(False))

    def _export_all_worker(self):
        import os
        scan_timestamp = SimpleDateFormat("yyyyMMdd_HHmmss").format(Date())
        base_dir = self._get_export_dir("scan_{}".format(scan_timestamp))
        if not base_dir:
            self._run_on_ui(lambda: JOptionPane.showMessageDialog(self._panel, "Cannot create export directory", "Error", JOptionPane.ERROR_MESSAGE))
            self._finish_export()
            self._run_on_ui(lambda: self._set_export_status("Export failed"))
            return

        try:
            all_issues = self._callbacks.getScanIssues(None) or []
            total_input = len(all_issues)
            seen = set()
            json_data = []

            for idx, issue in enumerate(all_issues):
                if self._is_export_cancelled():
                    self._callbacks.printOutput("[!] Export cancelled by user")
                    self._run_on_ui(lambda: JOptionPane.showMessageDialog(self._panel, "Export cancelled.", "Cancelled", JOptionPane.INFORMATION_MESSAGE))
                    self._run_on_ui(lambda: self._set_export_status("Export cancelled"))
                    return

                if idx == 0 or idx % 25 == 0:
                    progress_text = "Exporting issues... {}/{}".format(idx + 1, total_input)
                    self._run_on_ui(lambda msg=progress_text: self._set_export_status(msg))

                try:
                    severity = issue.getSeverity()
                    if severity not in ["High", "Medium"]:
                        continue

                    http_messages = issue.getHttpMessages()
                    if not http_messages:
                        continue

                    service = http_messages[0].getHttpService()
                    url = str(self._helpers.analyzeRequest(http_messages[0]).getUrl())
                    host = service.getHost()
                    issue_name = issue.getIssueName()
                    confidence = issue.getConfidence()

                    dedup_key = "{}{}{}".format(host, url, issue_name)
                    issue_hash = hashlib.md5(dedup_key.encode('utf-8')).hexdigest()
                    if issue_hash in seen:
                        continue
                    seen.add(issue_hash)

                    base_request = http_messages[0]
                    base_req_info = self._helpers.analyzeRequest(base_request)

                    insertion_points = []
                    for msg in http_messages:
                        req_info = self._helpers.analyzeRequest(msg)
                        params = req_info.getParameters()
                        for param in params:
                            param_type = ["URL", "Body", "Cookie"][param.getType()] if param.getType() < 3 else "Unknown"
                            point = "{}: {}".format(param_type, param.getName())
                            if point not in insertion_points:
                                insertion_points.append(point)

                    http_evidence = []
                    for msg in http_messages[:2]:
                        req_info = self._helpers.analyzeRequest(msg)
                        req_bytes = msg.getRequest()
                        req_body_offset = req_info.getBodyOffset()
                        req_body = self._helpers.bytesToString(req_bytes[req_body_offset:req_body_offset+5000]) if len(req_bytes) > req_body_offset else ""

                        resp_body = ""
                        status_code = None
                        if msg.getResponse():
                            resp_info = self._helpers.analyzeResponse(msg.getResponse())
                            resp_bytes = msg.getResponse()
                            resp_body_offset = resp_info.getBodyOffset()
                            resp_body = self._helpers.bytesToString(resp_bytes[resp_body_offset:resp_body_offset+5000]) if len(resp_bytes) > resp_body_offset else ""
                            status_code = resp_info.getStatusCode()

                        http_evidence.append({
                            "method": req_info.getMethod(),
                            "path": req_info.getUrl().getPath(),
                            "request_body": req_body,
                            "response_body": resp_body,
                            "status_code": status_code
                        })

                    query_params = {}
                    cookies = {}
                    for param in base_req_info.getParameters():
                        if param.getType() == 0:
                            query_params[param.getName()] = param.getValue()
                        elif param.getType() == 2:
                            cookies[param.getName()] = param.getValue()

                    curl_cmd = self._generate_curl(base_req_info, base_request)
                    python_template = self._generate_python(base_req_info, base_request, cookies)

                    json_data.append({
                        "id": issue_hash,
                        "timestamp": scan_timestamp,
                        "severity": severity,
                        "confidence": confidence,
                        "host": host,
                        "url": url,
                        "protocol": service.getProtocol(),
                        "port": service.getPort(),
                        "finding": issue_name,
                        "description": issue.getIssueDetail() or "N/A",
                        "background": issue.getIssueBackground() or "N/A",
                        "remediation": issue.getRemediationDetail() or "N/A",
                        "insertion_points": insertion_points,
                        "http_evidence": http_evidence,
                        "base_request": {
                            "method": base_req_info.getMethod(),
                            "path": base_req_info.getUrl().getPath(),
                            "query_string": base_req_info.getUrl().getQuery(),
                            "query_params": query_params,
                            "headers": [str(h) for h in base_req_info.getHeaders()[:20]],
                            "cookies": cookies,
                            "body": self._helpers.bytesToString(base_request.getRequest()[base_req_info.getBodyOffset():base_req_info.getBodyOffset()+5000])
                        },
                        "curl_command": curl_cmd,
                        "python_request_template": python_template
                    })
                except Exception as e:
                    self._callbacks.printError("Error: " + str(e))

            if self._is_export_cancelled():
                self._run_on_ui(lambda: self._set_export_status("Export cancelled"))
                return

            grouped = {}
            for item in json_data:
                sev = item["severity"]
                conf = item["confidence"]
                if sev not in grouped:
                    grouped[sev] = {}
                if conf not in grouped[sev]:
                    grouped[sev][conf] = []
                grouped[sev][conf].append(item)

            total = 0
            for severity in ["High", "Medium"]:
                if severity not in grouped:
                    continue
                sev_dir = os.path.join(base_dir, severity)
                File(sev_dir).mkdirs()

                for confidence in ["Certain", "Firm", "Tentative"]:
                    if confidence not in grouped[severity]:
                        continue

                    filename = os.path.join(sev_dir, confidence.lower() + ".json")
                    writer = None
                    try:
                        writer = FileWriter(filename)
                        writer.write(json.dumps(grouped[severity][confidence], indent=2))
                        total += len(grouped[severity][confidence])
                    finally:
                        if writer:
                            try:
                                writer.close()
                            except Exception as e:
                                self._callbacks.printError("Error closing file writer: " + str(e))

            stats = {"scan_timestamp": scan_timestamp, "total_issues": len(json_data), "by_severity": {}, "by_confidence": {}, "by_host": {}}
            for item in json_data:
                stats["by_severity"][item["severity"]] = stats["by_severity"].get(item["severity"], 0) + 1
                stats["by_confidence"][item["confidence"]] = stats["by_confidence"].get(item["confidence"], 0) + 1
                stats["by_host"][item["host"]] = stats["by_host"].get(item["host"], 0) + 1

            stats_file = os.path.join(base_dir, "stats.json")
            writer = None
            try:
                writer = FileWriter(stats_file)
                writer.write(json.dumps(stats, indent=2))
            finally:
                if writer:
                    try:
                        writer.close()
                    except Exception as e:
                        self._callbacks.printError("Error closing stats writer: " + str(e))

            readme = "# Burp Export - {}\n\nTotal: {} issues\nHigh: {}\nMedium: {}\nHosts: {}\n\n".format(
                scan_timestamp, len(json_data), stats["by_severity"].get("High", 0),
                stats["by_severity"].get("Medium", 0), len(stats["by_host"]))
            for sev in ["High", "Medium"]:
                if sev in grouped:
                    readme += "{}\\\n".format(sev)
                    for conf in ["Certain", "Firm", "Tentative"]:
                        if conf in grouped[sev]:
                            readme += "  {}.json ({})\n".format(conf.lower(), len(grouped[sev][conf]))
            writer = None
            try:
                writer = FileWriter(os.path.join(base_dir, "README.txt"))
                writer.write(readme)
            finally:
                if writer:
                    try:
                        writer.close()
                    except Exception as e:
                        self._callbacks.printError("Error closing README writer: " + str(e))

            script_content = ""
            script_name = "test.sh"
            count = 0

            if os.name == 'nt':
                script_content = "@echo off\necho Testing vulnerabilities...\necho.\n"
                script_name = "test.bat"
            else:
                script_content = "#!/bin/bash\necho 'Testing vulnerabilities...'\necho\n"

            for sev in ["High", "Medium"]:
                if sev not in grouped:
                    continue
                for conf in ["Certain", "Firm"]:
                    if conf not in grouped[sev]:
                        continue
                    for issue in grouped[sev][conf][:5]:
                        if issue.get("curl_command"):
                            count += 1
                            script_content += "echo '[{}] {}'\n".format(count, issue["finding"])
                            script_content += "{}\n".format(issue["curl_command"])
                            script_content += "echo\n"

            if os.name == 'nt':
                script_content += "pause\n"
            else:
                script_content += "read -p 'Press Enter to continue...'\n"

            script_path = os.path.join(base_dir, script_name)
            if self._write_file(script_path, script_content):
                if os.name != 'nt':
                    try:
                        import stat
                        os.chmod(script_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
                    except Exception as e:
                        self._callbacks.printError("Error setting chmod: " + str(e))

            self._callbacks.printOutput("[+] Exported {} issues to {}".format(total, base_dir))
            self._run_on_ui(lambda total_count=total, out_dir=base_dir: JOptionPane.showMessageDialog(
                self._panel,
                "Exported {} issues to:\n{}".format(total_count, out_dir),
                "Success",
                JOptionPane.INFORMATION_MESSAGE
            ))
            self._run_on_ui(lambda: self._set_export_status("Export completed: {} issues".format(total)))
        except Exception as e:
            self._callbacks.printError("Export failed: " + str(e))
            self._run_on_ui(lambda err=str(e): JOptionPane.showMessageDialog(
                self._panel,
                "Export failed:\n{}".format(err),
                "Error",
                JOptionPane.ERROR_MESSAGE
            ))
            self._run_on_ui(lambda: self._set_export_status("Export failed"))
        finally:
            self._finish_export()
    
    def _generate_curl(self, req_info, request):
        method = req_info.getMethod()
        url = str(req_info.getUrl())
        headers = req_info.getHeaders()
        body_offset = req_info.getBodyOffset()
        body = self._helpers.bytesToString(request.getRequest()[body_offset:body_offset+500])
        
        curl = "curl -X {} '{}'".format(method, url)
        for header in headers[1:15]:
            if ":" in header:
                curl += " -H '{}'".format(header)
        if body:
            curl += " -d '{}'".format(body.replace("'", "'\\'''"))
        return curl
    
    def _generate_python(self, req_info, request, cookies):
        method = req_info.getMethod()
        url = str(req_info.getUrl())
        headers_list = req_info.getHeaders()
        body_offset = req_info.getBodyOffset()
        body = self._helpers.bytesToString(request.getRequest()[body_offset:body_offset+500])
        
        headers_dict = {}
        for header in headers_list[1:]:
            if ":" in header:
                key, val = header.split(":", 1)
                if key.lower() not in ["host", "content-length", "cookie"]:
                    headers_dict[key.strip()] = val.strip()
        
        template = "import requests\n\n"
        template += "url = '{}'\n".format(url)
        template += "headers = {}\n".format(json.dumps(headers_dict, indent=4))
        if cookies:
            template += "cookies = {}\n".format(json.dumps(cookies, indent=4))
        if body:
            template += "data = '''{}'''\n".format(body[:500])
        
        template += "\nresponse = requests.{}(url, headers=headers".format(method.lower())
        if cookies:
            template += ", cookies=cookies"
        if body:
            template += ", data=data"
        template += ")\n"
        template += "print(f'Status: {response.status_code}')\n"
        template += "print(f'Response: {response.text[:500]}')\n"
        
        return template
    
    def _get_status_file(self):
        import os
        paths = []
        if os.name == 'nt':
            paths.append(os.path.join("C:\\", "burp_exports", "issue_status.json"))
        paths.append(os.path.join(os.path.expanduser("~"), "burp_exports", "issue_status.json"))
        
        for path in paths:
            if File(path).exists():
                return path
        return paths[-1]
    
    def _read_file(self, filepath):
        reader = None
        try:
            f = File(filepath)
            if not f.exists():
                return None
            reader = BufferedReader(FileReader(f))
            content = ""
            line = reader.readLine()
            while line:
                content += line
                line = reader.readLine()
            return content
        except Exception as e:
            self._callbacks.printError("Error reading file: " + str(e))
            return None
        finally:
            if reader:
                try:
                    reader.close()
                except Exception as e:
                    self._callbacks.printError("Error closing reader: " + str(e))
    
    def _write_file(self, filepath, content):
        writer = None
        try:
            writer = FileWriter(filepath)
            writer.write(content)
            return True
        except Exception as e:
            self._callbacks.printError("Error writing file: " + str(e))
            return False
        finally:
            if writer:
                try:
                    writer.close()
                except Exception as e:
                    self._callbacks.printError("Error closing file writer: " + str(e))
    
    def _load_status(self):
        status_file = self._get_status_file()
        content = self._read_file(status_file)
        if content:
            try:
                return json.loads(content)
            except Exception as e:
                self._callbacks.printError("Error loading status: " + str(e))
        return {}
    
    def _save_status(self):
        import os
        export_dir = self._get_export_dir()
        if not export_dir:
            return
        status_file = os.path.join(export_dir, "issue_status.json")
        self._write_file(status_file, json.dumps(self.issue_status, indent=2))
    
    def _get_status_str(self, issue_id):
        status = self.issue_status.get(issue_id, {})
        tags = []
        if status.get("tested"): tags.append("T")
        if status.get("exploited"): tags.append("E")
        if status.get("fp"): tags.append("FP")
        return " [{}]".format(",".join(tags)) if tags else ""
    
    def _on_selection_change(self):
        key = self._get_selected_issue_key()
        if not key:
            self.tested_cb.setSelected(False)
            self.exploited_cb.setSelected(False)
            self.fp_cb.setSelected(False)
            return

        issue_data = self.issues_cache.get(key)
        if issue_data:
            issue_id = issue_data.get("id")
            status = self.issue_status.get(issue_id, {})
            self.tested_cb.setSelected(status.get("tested", False))
            self.exploited_cb.setSelected(status.get("exploited", False))
            self.fp_cb.setSelected(status.get("fp", False))
    
    def _update_status(self):
        key = self._get_selected_issue_key()
        if key:
            issue_data = self.issues_cache.get(key)
            if issue_data:
                issue_id = issue_data.get("id")
                self.issue_status[issue_id] = {
                    "tested": self.tested_cb.isSelected(),
                    "exploited": self.exploited_cb.isSelected(),
                    "fp": self.fp_cb.isSelected()
                }
                self._save_status()
    
    def _clear_status(self):
        key = self._get_selected_issue_key()
        if key:
            issue_data = self.issues_cache.get(key)
            if issue_data:
                issue_id = issue_data.get("id")
                if issue_id in self.issue_status:
                    del self.issue_status[issue_id]
                self._save_status()
                self.tested_cb.setSelected(False)
                self.exploited_cb.setSelected(False)
                self.fp_cb.setSelected(False)

class UiRunnable(Runnable):
    def __init__(self, fn):
        self.fn = fn

    def run(self):
        self.fn()

class AlternatingRowRenderer(ListCellRenderer):
    def __init__(self, extender):
        self.extender = extender
    
    def getListCellRendererComponent(self, list, value, index, isSelected, cellHasFocus):
        row = None
        if index >= 0 and index < len(self.extender.displayed_rows):
            row = self.extender.displayed_rows[index]
        is_header = row and row.get("type") == "header"
        issue_key = row.get("issue_key") if row else None

        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.X_AXIS))
        panel.setOpaque(True)
        
        text_label = JLabel(str(value))
        text_label.setFont(Font("Monospaced", Font.BOLD if is_header else Font.PLAIN, 12))
        panel.add(text_label)
        
        if issue_key and issue_key not in self.extender.duplicate_issue_keys:
            panel.add(Box.createHorizontalGlue())
            unique_label = JLabel("[UNIQUE]")
            unique_label.setFont(Font("Monospaced", Font.BOLD, 12))
            unique_label.setForeground(Color(0, 100, 0))
            panel.add(unique_label)
        
        if isSelected:
            panel.setBackground(Color(184, 207, 229))
            text_label.setForeground(Color.BLACK)
        elif is_header:
            panel.setBackground(Color(232, 232, 232))
            text_label.setForeground(Color(60, 60, 60))
        elif issue_key and issue_key in self.extender.copied_issue_keys:
            panel.setBackground(Color(200, 255, 200))
            text_label.setForeground(Color.BLACK)
        elif index % 2 == 0:
            panel.setBackground(Color.WHITE)
            text_label.setForeground(Color.BLACK)
        else:
            panel.setBackground(Color(245, 245, 245))
            text_label.setForeground(Color.BLACK)
        
        return panel

class DoubleClickListener(MouseAdapter):
    def __init__(self, extender):
        self.extender = extender
    
    def mouseClicked(self, event):
        if event.getClickCount() == 2:
            key = self.extender._get_selected_issue_key()
            if not key:
                return

            issue_data = self.extender.issues_cache.get(key)
            if issue_data:
                try:
                    prompt = issue_data.get("prompt")
                    if not prompt:
                        prompt = self.extender._build_issue_prompt(issue_data.get("issue"))
                        issue_data["prompt"] = prompt

                    if not prompt:
                        raise ValueError("No prompt data available")

                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(prompt), None)
                    self.extender.copied_issue_keys.add(key)
                    self.extender.issue_list.repaint()
                    JOptionPane.showMessageDialog(self.extender._panel, "Copied to clipboard!", "Success", JOptionPane.INFORMATION_MESSAGE)
                except Exception as e:
                    JOptionPane.showMessageDialog(self.extender._panel, "Failed: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
            else:
                JOptionPane.showMessageDialog(self.extender._panel, "No data found", "Error", JOptionPane.ERROR_MESSAGE)

class SearchListener(DocumentListener):
    def __init__(self, extender):
        self.extender = extender
    
    def insertUpdate(self, e):
        self.extender._apply_filters()
    
    def removeUpdate(self, e):
        self.extender._apply_filters()
    
    def changedUpdate(self, e):
        self.extender._apply_filters()

class UpdateCountsListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    
    def actionPerformed(self, e):
        self.extender._update_button_counts()
