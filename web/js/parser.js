class XMLParser {
    static parseXML(xmlString) {
        const parser = new DOMParser();
        const xmlDoc = parser.parseFromString(xmlString, "text/xml");
        
        if (xmlDoc.parsererror) {
            throw new Error("Invalid XML: " + xmlDoc.parsererror.textContent);
        }

        const findings = [];
        const findingElements = xmlDoc.querySelectorAll("finding");

        findingElements.forEach((element) => {
            const finding = {
                url: this.getElementText(element, "url"),
                parameter: this.getElementText(element, "parameter"),
                method: this.getElementText(element, "method"),
                confidence: this.getElementText(element, "confidence"),
                false_positive: this.getElementText(element, "false_positive") === "true",
                verdict: this.getElementText(element, "verdict"),
                test_steps: this.parseTestSteps(element)
            };
            findings.push(finding);
        });

        return findings;
    }

    static parseTestSteps(findingElement) {
        const testSteps = [];
        const testElements = findingElement.querySelectorAll("test_steps > test");

        testElements.forEach((testElement) => {
            const test = {
                step_name: this.getElementText(testElement, "step_name"),
                payload: this.getElementText(testElement, "payload"),
                result: this.getElementText(testElement, "result"),
                request: this.parseRequest(testElement),
                response: this.parseResponse(testElement)
            };
            testSteps.push(test);
        });

        return testSteps;
    }

    static parseRequest(testElement) {
        const requestElement = testElement.querySelector("request");
        if (!requestElement) return null;

        return {
            method: this.getElementText(requestElement, "method"),
            path: this.getElementText(requestElement, "path"),
            headers: this.parseHeaders(requestElement.querySelector("headers")),
            body: this.getElementText(requestElement, "body")
        };
    }

    static parseResponse(testElement) {
        const responseElement = testElement.querySelector("response");
        if (!responseElement) return null;

        return {
            status_code: this.getElementText(responseElement, "status_code"),
            reason: this.getElementText(responseElement, "reason"),
            headers: this.parseHeaders(responseElement.querySelector("headers")),
            body: this.getElementText(responseElement, "body")
        };
    }

    static parseHeaders(headersElement) {
        const headers = {};
        if (!headersElement) return headers;

        headersElement.querySelectorAll("header").forEach((headerElement) => {
            const name = headerElement.getAttribute("name");
            const value = headerElement.textContent;
            headers[name] = value;
        });

        return headers;
    }

    static getElementText(parentElement, tagName) {
        const element = parentElement.querySelector(tagName);
        return element ? element.textContent.trim() : "";
    }
}
