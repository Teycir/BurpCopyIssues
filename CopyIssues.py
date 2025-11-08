# pylint: disable=import-error
from burp import IBurpExtender, ITab
from javax.swing import JPanel, JButton, JList, JScrollPane, DefaultListModel, JOptionPane, BorderFactory, ListCellRenderer, JLabel, JCheckBox, BoxLayout, Box, JTextField, JComboBox
from java.awt import BorderLayout, GridLayout, Toolkit, Color, Font, FlowLayout, Component
from javax.swing.event import DocumentListener
from java.awt.datatransfer import StringSelection
from java.awt.event import MouseAdapter
from java.io import File, FileWriter, FileReader, BufferedReader
from java.text import SimpleDateFormat
from java.util import Date
import hashlib
import json
import re

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("CopyIssues")
        
        self.issues_cache = {}
        self.all_issues_data = []
        self.issue_status = self._load_status()
        self.copied_indices = set()
        self.duplicate_indices = set()
        self.list_model = DefaultListModel()
        self.issue_list = JList(self.list_model)
        self.issue_list.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.issue_list.setCellRenderer(AlternatingRowRenderer(self))
        self.issue_list.addMouseListener(DoubleClickListener(self))
        self.current_filter = {"severity": None, "confidence": None}
        self.filter_buttons = {}
        
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
        
        self._update_button_counts()
        
        export_btn = JButton("Export All")
        export_btn.setBackground(Color(40, 167, 69))
        export_btn.setForeground(Color.WHITE)
        export_btn.addActionListener(lambda e: self.export_all())
        
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
        btn_panel.add(export_btn)
        btn_panel.add(refresh_btn)
        
        self._panel.add(btn_panel, BorderLayout.NORTH)
        callbacks.addSuiteTab(self)

    def getTabCaption(self):
        count = self.list_model.getSize()
        return "CopyIssues" if count == 0 else "CopyIssues ({})".format(count)
    
    def getUiComponent(self):
        return self._panel
    
    def refresh_current(self):
        if self.current_filter["severity"] and self.current_filter["confidence"]:
            self.copied_indices.clear()
            self.load_issues(self.current_filter["severity"], self.current_filter["confidence"])
        else:
            self._callbacks.printOutput("[!] No filter active - click a severity/confidence button first")
    
    def _update_button_counts(self):
        all_issues = self._callbacks.getScanIssues(None)
        counts = {}
        for issue in all_issues:
            sev = issue.getSeverity()
            conf = issue.getConfidence()
            if sev in ["High", "Medium"]:
                key = (sev, conf)
                counts[key] = counts.get(key, 0) + 1
        
        for key, btn in self.filter_buttons.items():
            count = counts.get(key, 0)
            text = "{} - {} ({})".format(key[0], key[1], count)
            btn.setText(text)
    
    def load_issues(self, severity, confidence):
        self.current_filter = {"severity": severity, "confidence": confidence}
        self.copied_indices.clear()
        self.duplicate_indices.clear()
        issues = [i for i in self._callbacks.getScanIssues(None)
                  if i.getSeverity() == severity and i.getConfidence() == confidence]
        
        self.all_issues_data = []
        self.list_model.clear()
        self.issues_cache.clear()
        
        if not issues:
            self._callbacks.printOutput("[!] No {} {} issues found".format(severity, confidence))
            return
        
        # Count duplicates per host
        dup_counts = {}
        for issue in issues:
            http_messages = issue.getHttpMessages()
            if http_messages:
                service = http_messages[0].getHttpService()
                host = service.getHost()
                issue_name = issue.getIssueName()
                key = "{}:{}".format(host, issue_name)
                dup_counts[key] = dup_counts.get(key, 0) + 1
        
        for idx, issue in enumerate(issues):
            try:
                http_messages = issue.getHttpMessages()
                service = http_messages[0].getHttpService() if http_messages else None
                host = service.getHost() if service else ""
                issue_name = issue.getIssueName()
                issue_id = hashlib.md5("{}{}{}".format(host, str(issue.getUrl()), issue_name).encode('utf-8')).hexdigest()
                
                dup_key = "{}:{}".format(host, issue_name)
                count = dup_counts.get(dup_key, 1)
                if count > 1:
                    self.duplicate_indices.add(idx)
                
                key = "[{}] {} - {}".format(idx + 1, issue_name, str(issue.getUrl()))
                self.list_model.addElement(key)
                self.issues_cache[key] = {"prompt": None, "id": issue_id}
                
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
                except:
                    pass
                
                references = ""
                try:
                    refs = issue.getReferences()
                    if refs:
                        references = "\n\nReferences:\n" + '\n'.join(['- ' + str(r) for r in refs[:3]])
                except:
                    pass
                
                prompt = """=== BURP SCAN FINDING ===
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
                
                self.issues_cache[key]["prompt"] = prompt
                self.all_issues_data.append({"key": key, "host": host, "issue_name": issue_name, "url": str(issue.getUrl())})
            except Exception as e:
                self._callbacks.printError("Error processing issue")
        
        self._callbacks.printOutput("[+] Loaded {} {} {} issues".format(len(issues), severity, confidence))
        self._callbacks.setExtensionName("CopyIssues ({})".format(len(issues)))
    
    def _apply_filters(self):
        search_text = self.search_field.getText().lower()
        sort_by = self.sort_combo.getSelectedItem()
        
        filtered = [d for d in self.all_issues_data if search_text in d["key"].lower()]
        
        if sort_by == "Host":
            filtered.sort(key=lambda x: x["host"])
        elif sort_by == "Issue Type":
            filtered.sort(key=lambda x: x["issue_name"])
        elif sort_by == "URL":
            filtered.sort(key=lambda x: x["url"])
        
        self.list_model.clear()
        for d in filtered:
            self.list_model.addElement(d["key"])
        
        self._callbacks.setExtensionName("CopyIssues ({})".format(len(filtered)))
    
    def _toggle_grouping(self):
        if not self.all_issues_data:
            return
        
        grouped = {}
        for d in self.all_issues_data:
            host = d["host"]
            if host not in grouped:
                grouped[host] = []
            grouped[host].append(d["key"])
        
        self.list_model.clear()
        for host in sorted(grouped.keys()):
            self.list_model.addElement("=== {} ({}) ===".format(host, len(grouped[host])))
            for key in grouped[host]:
                self.list_model.addElement("  " + key)
        
        self._callbacks.setExtensionName("CopyIssues ({})".format(len(self.all_issues_data)))
    
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
            except Exception:
                continue
        return None
    
    def export_all(self):
        scan_timestamp = SimpleDateFormat("yyyyMMdd_HHmmss").format(Date())
        base_dir = self._get_export_dir("scan_{}".format(scan_timestamp))
        
        if not base_dir:
            JOptionPane.showMessageDialog(self._panel, "Cannot create export directory", "Error", JOptionPane.ERROR_MESSAGE)
            return
        
        all_issues = self._callbacks.getScanIssues(None)
        seen = set()
        json_data = []
        
        for issue in all_issues:
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
                
                # Extract insertion points
                insertion_points = []
                for msg in http_messages:
                    req_info = self._helpers.analyzeRequest(msg)
                    params = req_info.getParameters()
                    for param in params:
                        param_type = ["URL", "Body", "Cookie"][param.getType()] if param.getType() < 3 else "Unknown"
                        point = "{}: {}".format(param_type, param.getName())
                        if point not in insertion_points:
                            insertion_points.append(point)
                
                # Extract HTTP evidence (limit to first 2 messages for performance)
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
                
                # Extract query params and cookies
                query_params = {}
                cookies = {}
                for param in base_req_info.getParameters():
                    if param.getType() == 0:
                        query_params[param.getName()] = param.getValue()
                    elif param.getType() == 2:
                        cookies[param.getName()] = param.getValue()
                
                # Generate curl command
                curl_cmd = self._generate_curl(base_req_info, base_request)
                
                # Generate Python template
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
        
        # Group and write files
        import os
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
                        except:
                            pass
        
        # Generate stats
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
                except:
                    pass
        
        # Generate README
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
                except:
                    pass
        
        # Generate test script
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
                except Exception:
                    pass
        
        JOptionPane.showMessageDialog(self._panel, "Exported {} issues to:\n{}".format(total, base_dir), "Success", JOptionPane.INFORMATION_MESSAGE)
        self._callbacks.printOutput("[+] Exported {} issues to {}".format(total, base_dir))
    
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
        except Exception:
            return None
        finally:
            if reader:
                try:
                    reader.close()
                except Exception:
                    pass
    
    def _write_file(self, filepath, content):
        writer = None
        try:
            writer = FileWriter(filepath)
            writer.write(content)
            return True
        except Exception:
            return False
        finally:
            if writer:
                try:
                    writer.close()
                except Exception:
                    pass
    
    def _load_status(self):
        status_file = self._get_status_file()
        content = self._read_file(status_file)
        if content:
            try:
                return json.loads(content)
            except Exception:
                pass
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
        idx = self.issue_list.getSelectedIndex()
        if idx >= 0:
            key = self.list_model.getElementAt(idx)
            issue_data = self.issues_cache.get(key)
            if issue_data:
                issue_id = issue_data.get("id")
                status = self.issue_status.get(issue_id, {})
                self.tested_cb.setSelected(status.get("tested", False))
                self.exploited_cb.setSelected(status.get("exploited", False))
                self.fp_cb.setSelected(status.get("fp", False))
    
    def _update_status(self):
        idx = self.issue_list.getSelectedIndex()
        if idx >= 0:
            key = self.list_model.getElementAt(idx)
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
        idx = self.issue_list.getSelectedIndex()
        if idx >= 0:
            key = self.list_model.getElementAt(idx)
            issue_data = self.issues_cache.get(key)
            if issue_data:
                issue_id = issue_data.get("id")
                if issue_id in self.issue_status:
                    del self.issue_status[issue_id]
                self._save_status()
                self.tested_cb.setSelected(False)
                self.exploited_cb.setSelected(False)
                self.fp_cb.setSelected(False)

class AlternatingRowRenderer(ListCellRenderer):
    def __init__(self, extender):
        self.extender = extender
    
    def getListCellRendererComponent(self, list, value, index, isSelected, cellHasFocus):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.X_AXIS))
        panel.setOpaque(True)
        
        text_label = JLabel(str(value))
        text_label.setFont(Font("Monospaced", Font.PLAIN, 12))
        panel.add(text_label)
        
        if index not in self.extender.duplicate_indices:
            panel.add(Box.createHorizontalGlue())
            unique_label = JLabel("[UNIQUE]")
            unique_label.setFont(Font("Monospaced", Font.BOLD, 12))
            unique_label.setForeground(Color(0, 100, 0))
            panel.add(unique_label)
        
        if isSelected:
            panel.setBackground(Color(184, 207, 229))
            text_label.setForeground(Color.BLACK)
        elif index in self.extender.copied_indices:
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
            idx = self.extender.issue_list.getSelectedIndex()
            if idx >= 0:
                key = self.extender.list_model.getElementAt(idx)
                issue_data = self.extender.issues_cache.get(key)
                if issue_data and issue_data.get("prompt"):
                    try:
                        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(issue_data["prompt"]), None)
                        self.extender.copied_indices.add(idx)
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
