class XMLParser {
    static parseXML(xmlString) {
        const parser = new DOMParser();
        const xmlDoc = parser.parseFromString(xmlString, "text/xml");
        
        if (xmlDoc.parsererror) {
            throw new Error("Invalid XML: " + xmlDoc.parsererror.textContent);
        }

        console.log('XML loaded, root element:', xmlDoc.documentElement.tagName);
        
        const findings = [];
        
        // Burp Suite format: <issues><issue>...</issue></issues>
        const issueElements = xmlDoc.querySelectorAll("issue");
        console.log('Total issues found:', issueElements.length);

        issueElements.forEach((element, idx) => {
            try {
                const issueName = this.getElementText(element, "name");
                const issueBackground = this.getElementText(element, "issueBackground");
                
                console.log(`Issue ${idx}: ${issueName}`);
                
                // Check if it's a SQLi issue
                if (this.isSQLiIssue(issueName, issueBackground)) {
                    const issue = this.parseIssue(element);
                    if (issue) {
                        findings.push(issue);
                        console.log(`  ✓ SQLi issue parsed`);
                    }
                } else {
                    console.log(`  ✗ Skipped (not SQLi): ${issueName}`);
                }
            } catch (e) {
                console.warn(`Error parsing issue ${idx}:`, e.message);
            }
        });

        console.log('Total SQLi findings parsed:', findings.length);
        
        if (findings.length === 0) {
            console.warn('⚠️ No SQLi issues found in this Burp report');
        }
        
        return findings;
    }

    static isSQLiIssue(name, background) {
        const combined = (name + " " + background).toLowerCase();
        const sqlKeywords = [
            "sql injection",
            "sql",
            "sqli",
            "sql-injection",
            "database"
        ];
        return sqlKeywords.some(keyword => combined.includes(keyword));
    }

    static parseIssue(issueElement) {
        // Extract basic information
        const name = this.getElementText(issueElement, "name") || "Unknown";
        const urlElement = issueElement.querySelector("host");
        const url = urlElement ? urlElement.textContent : "";
        const path = this.getElementText(issueElement, "path") || "/";
        const location = this.getElementText(issueElement, "location") || "";
        const severity = this.getElementText(issueElement, "severity") || "Unknown";
        const confidence = this.getElementText(issueElement, "confidence") || "Unknown";
        const issueBackground = this.getElementText(issueElement, "issueBackground") || "";
        const issueDetail = this.getElementText(issueElement, "issueDetail") || "";
        
        // Extract parameter from location
        let parameter = "";
        const paramMatch = location.match(/\[parameter:\s*([^\]]+)\]|parameter:\s*([^\s,]+)/i);
        if (paramMatch) {
            parameter = paramMatch[1] || paramMatch[2];
        }

        // Determine method from request
        let method = "GET";
        const requests = issueElement.querySelectorAll("request");
        if (requests.length > 0) {
            const firstRequest = requests[0].textContent || "";
            if (firstRequest.toUpperCase().includes("POST")) {
                method = "POST";
            }
        }

        // Get request/response details
        const testSteps = this.extractTestSteps(issueElement);

        return {
            url: url + path,
            parameter: parameter || "unknown",
            method: method,
            confidence: this.normalizeConfidence(confidence),
            false_positive: false, // Burp findings are assumed true positives initially
            verdict: `${name} (${severity}) - ${confidence}`,
            issue_name: name,
            severity: severity,
            background: issueBackground,
            detail: issueDetail,
            test_steps: testSteps
        };
    }

    static extractTestSteps(issueElement) {
        const testSteps = [];
        const requests = issueElement.querySelectorAll("request");
        const responses = issueElement.querySelectorAll("response");

        if (requests.length > 0) {
            const request = this.parseRequest(requests[0]);
            const response = responses.length > 0 ? this.parseResponse(responses[0]) : null;

            testSteps.push({
                step_name: "Burp Scanner Finding",
                payload: "[Scanner Detection]",
                request: request,
                response: response,
                result: "Issue detected by Burp Suite Scanner"
            });
        }

        return testSteps;
    }

    static parseRequest(requestElement) {
        const isBase64 = requestElement.getAttribute("base64") === "true";
        let rawRequest = requestElement.textContent || "";
        
        // Decode if base64
        if (isBase64) {
            try {
                rawRequest = atob(rawRequest);
            } catch (e) {
                console.warn("Failed to decode base64 request");
            }
        }
        
        // Parse HTTP request
        const lines = rawRequest.split('\n');
        const firstLine = lines[0] || "";
        
        let method = "GET";
        let path = "/";
        
        if (firstLine.toUpperCase().includes("POST")) {
            method = "POST";
        } else if (firstLine.toUpperCase().includes("GET")) {
            method = "GET";
        }
        
        // Extract path
        const pathMatch = firstLine.match(/\s(\/[^\s]*)/);
        if (pathMatch) {
            path = pathMatch[1];
        }

        // Extract headers
        const headers = {};
        let bodyStartIndex = 0;
        for (let i = 1; i < lines.length; i++) {
            if (lines[i].trim() === "") {
                bodyStartIndex = i + 1;
                break;
            }
            const headerMatch = lines[i].match(/([^:]+):\s*(.+)/);
            if (headerMatch) {
                headers[headerMatch[1].trim()] = headerMatch[2].trim();
            }
        }

        // Extract body
        const body = lines.slice(bodyStartIndex).join('\n').trim();

        return {
            method: method,
            path: path,
            headers: headers,
            body: body.substring(0, 2000)
        };
    }

    static parseResponse(responseElement) {
        const isBase64 = responseElement.getAttribute("base64") === "true";
        let rawResponse = responseElement.textContent || "";
        
        // Decode if base64
        if (isBase64) {
            try {
                rawResponse = atob(rawResponse);
            } catch (e) {
                console.warn("Failed to decode base64 response");
            }
        }
        
        // Parse HTTP response
        const lines = rawResponse.split('\n');
        const firstLine = lines[0] || "";
        
        let statusCode = "200";
        let reason = "OK";
        
        // Extract status code
        const statusMatch = firstLine.match(/(\d{3})\s+(.+)/);
        if (statusMatch) {
            statusCode = statusMatch[1];
            reason = statusMatch[2];
        }

        // Extract headers
        const headers = {};
        let bodyStartIndex = 0;
        for (let i = 1; i < lines.length; i++) {
            if (lines[i].trim() === "") {
                bodyStartIndex = i + 1;
                break;
            }
            const headerMatch = lines[i].match(/([^:]+):\s*(.+)/);
            if (headerMatch) {
                headers[headerMatch[1].trim()] = headerMatch[2].trim();
            }
        }

        // Extract body
        const body = lines.slice(bodyStartIndex).join('\n').trim();

        return {
            status_code: statusCode,
            reason: reason,
            headers: headers,
            body: body.substring(0, 2000)
        };
    }

    static getElementText(parentElement, tagName) {
        const element = parentElement.querySelector(tagName);
        if (!element) return "";
        
        // Remove HTML tags if present
        let text = element.textContent || "";
        text = text.replace(/<[^>]*>/g, '').trim();
        
        return text;
    }

    static normalizeConfidence(confidence) {
        const lower = confidence.toLowerCase();
        if (lower.includes("definite") || lower.includes("certain")) return "Certain";
        if (lower.includes("firm")) return "Firm";
        if (lower.includes("tentative")) return "Tentative";
        return confidence || "Firm";
    }
}
