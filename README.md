# SQLI-FP: SQL Injection False Positive Detector

A comprehensive toolkit for automated SQL Injection vulnerability testing with intelligent false positive elimination. Parse Burp Suite reports, actively test findings, and visualize results with an interactive web interface.

## 🎯 Features

✅ **Burp Suite Integration**
- Parses XML reports from Burp Suite Pro
- Extracts SQLi findings automatically
- Preserves confidence levels and metadata

✅ **Multi-Method SQLi Testing**
- **Error-Based**: Detects database error messages
- **Boolean-Blind**: Analyzes response differences
- **Time-Based**: Measures execution delays
- **Syntax Repair**: Tests comment-based bypasses

✅ **Structured XML Output**
- Complete HTTP request/response logs
- All test payloads and results documented
- True positive / False positive classification
- Ready for integration with other tools

✅ **Interactive Web Dashboard**
- Real-time filtering and search
- Statistics dashboard with metrics
- Detailed finding inspection
- Full request/response visibility
- Export to JSON format
- Mobile-responsive design

## 📁 Project Structure

```
SQLI-FP/
├── sqli_triage.py              # Main Python testing script
├── web/                        # Web interface
│   ├── index.html             # Dashboard UI
│   ├── css/
│   │   └── style.css          # Styling
│   └── js/
│       ├── parser.js          # XML parser
│       └── app.js             # Frontend logic
├── README.md                   # This file
└── .gitignore
```

## 🚀 Quick Start

### Prerequisites

- Python 3.7+
- Modern web browser
- Required packages: `requests`, `beautifulsoup4`, `lxml`

### Installation

```bash
# Clone repository
git clone https://github.com/YoussefFeki004/SQLI-FP.git
cd SQLI-FP

# Install dependencies
pip install requests beautifulsoup4 lxml
```

### Configuration

Edit `sqli_triage.py` to set your test parameters:

```python
# Input file from Burp Suite
BURP_XML_FILE = "burp_report.xml"

# Output report
OUTPUT_XML_FILE = "sqli_triage_results.xml"

# Authentication
GLOBAL_COOKIES = {
    "session": "YOUR_SESSION_COOKIE_VALUE"
}

# Timeouts
TIME_DELAY_THRESHOLD = 5.0      # Seconds for time-based tests
TIMEOUT_LIMIT = 12.0            # HTTP request timeout
```

## 💻 Usage

### Step 1: Run Active Testing

```bash
python sqli_triage.py
```

This will:
1. Parse your Burp XML report
2. Extract SQLi findings
3. Test each with multiple payloads
4. Generate `sqli_triage_results.xml` with results
5. Display summary statistics

### Step 2: View Results

1. Open `web/index.html` in your browser
2. Click "Upload XML Report"
3. Select the generated XML file
4. Explore findings interactively

## 🔍 Testing Methods

### Error-Based SQLi
Tests if SQL syntax errors return database error messages.

**Payload**: `'`

**Detection**: Database error patterns (SQLSTATE, syntax error, etc.)

### Syntax Comment Repair
Tests if comment sequences repair broken SQL queries.

**Payload**: `' --`

**Detection**: Status code change from error to 200 OK

### Boolean-Blind SQLi
Compares responses between true and false conditions.

**Payloads**:
- `' AND '1'='1'--` (True)
- `' AND '1'='2'--` (False)

**Detection**: Response size or status code differences

### Time-Based Blind SQLi
Measures response delays from SLEEP() execution.

**Payload**: `' AND (SELECT 1 FROM (SELECT(SLEEP(5)))x)--`

**Detection**: Response time >= TIME_DELAY_THRESHOLD

## 📊 Web Interface

### Dashboard
- **Total Findings**: Count of all tested vulnerabilities
- **True Positives**: Confirmed exploitable SQLi
- **False Positives**: Non-exploitable findings
- **Success Rate**: % of true positives

### Filters
- Search by URL (partial match)
- Filter by status (True/False Positive)
- Filter by HTTP method (GET/POST)
- Filter by confidence level (Certain/Firm/Tentative)

### Details View
- Full vulnerability metadata
- All test steps performed
- Complete HTTP request/response logs
- Payload and result for each test
- Collapsible request/response bodies

### Export
- Download filtered results as JSON
- Preserve all metadata and test data

## 📋 Output Format

### XML Structure

```xml
<findings>
  <finding>
    <url>http://target.com/search?q=test</url>
    <parameter>q</parameter>
    <method>GET</method>
    <confidence>Certain</confidence>
    <false_positive>false</false_positive>
    <verdict>TRUE POSITIVE (In-Band: Database error detected)</verdict>
    <test_steps>
      <test>
        <step_name>ERROR INJECTION TEST</step_name>
        <payload>'</payload>
        <request>
          <method>GET</method>
          <path>/search?q=%27</path>
          <headers>...</headers>
          <body></body>
        </request>
        <response>
          <status_code>500</status_code>
          <reason>Internal Server Error</reason>
          <headers>...</headers>
          <body>SQL Error: Syntax error...</body>
        </response>
        <result>Error injection attempted</result>
      </test>
    </test_steps>
  </finding>
</findings>
```

## 🔧 Customization

### Add Custom Payloads

Modify the payload strings in `sqli_triage.py`:

```python
err_payload = "'"  # Error-based
comment_payload = "' --"  # Comment repair
true_payload = "' AND '1'='1'--"  # Boolean true
false_payload = "' AND '1'='2'--"  # Boolean false
time_payload = "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))x)--"  # Time-based
```

### Adjust Thresholds

```python
TIME_DELAY_THRESHOLD = 5.0  # Increase for slower networks
TIMEOUT_LIMIT = 12.0         # Increase for slow targets
```

### Add Database Error Patterns

```python
DB_ERRORS = [
    r"SQLSTATE",
    r"ORA-",  # Oracle
    r"DB2",   # IBM DB2
    # Add more patterns...
]
```

## ⚠️ Important Notes

1. **Authorization**: Only test systems you own or have explicit permission to test
2. **Session Management**: Ensure cookies/tokens are valid before running
3. **Rate Limiting**: Adjust TIME_DELAY_THRESHOLD if server has strict timeouts
4. **Network**: Time-based tests require stable network connections
5. **WAF/IPS**: Some payloads may trigger security systems

## 🐛 Troubleshooting

### "File not found" Error
- Ensure `burp_report.xml` is in the same directory as the script
- Check file name matches `BURP_XML_FILE` variable

### "Endpoint unreachable"
- Verify target is still accessible
- Check session/cookie validity
- Confirm network connectivity

### "No SQLi findings"
- Verify Burp report contains SQLi issues
- Check XML file is properly formatted
- Ensure issue names contain "SQL" keyword

### XML Parse Errors
- Ensure file encoding is UTF-8
- Validate XML structure with online validators
- Re-export from Burp Suite if corrupted

## 📈 Roadmap

- [ ] STACKED QUERIES support
- [ ] UNION-based SQLi detection
- [ ] Second-order SQLi testing
- [ ] Database fingerprinting
- [ ] Automated data extraction
- [ ] Custom SQLi rule engine
- [ ] API integration (reports to external tools)

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

MIT License - See LICENSE file for details

## ⚖️ Legal Disclaimer

**This tool is intended for authorized security testing ONLY.**

Unauthorized access to computer systems is illegal. Users are responsible for:
- Obtaining proper authorization before testing
- Complying with all applicable laws and regulations
- Respecting system owners' privacy and security

The authors assume no liability for misuse or damage caused by this tool.

---

**Author**: Youssef Feki  
**Repository**: https://github.com/YoussefFeki004/SQLI-FP  
**Created**: 2026  
**License**: MIT
