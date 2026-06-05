let allFindings = [];
let filteredFindings = [];
const modal = new bootstrap.Modal(document.getElementById('detailModal'));
const uploadModal = new bootstrap.Modal(document.getElementById('uploadModal'));

function openUploadModal() {
    document.getElementById('uploadError').classList.add('d-none');
    document.getElementById('xmlFile').value = '';
    uploadModal.show();
}

function handleFileUpload() {
    const fileInput = document.getElementById('xmlFile');
    const file = fileInput.files[0];

    if (!file) {
        showUploadError('Please select a file');
        return;
    }

    if (!file.name.endsWith('.xml')) {
        showUploadError('Please select a valid XML file');
        return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
        try {
            allFindings = XMLParser.parseXML(e.target.result);
            filteredFindings = [...allFindings];
            uploadModal.hide();
            renderDashboard();
            renderFindings();
        } catch (error) {
            showUploadError('Error parsing XML: ' + error.message);
        }
    };
    reader.readAsText(file);
}

function showUploadError(message) {
    const errorDiv = document.getElementById('uploadError');
    errorDiv.textContent = message;
    errorDiv.classList.remove('d-none');
}

function renderDashboard() {
    const dashboard = document.getElementById('dashboard');
    const emptyState = document.getElementById('emptyState');
    const filtersCard = document.getElementById('filtersCard');
    const findingsCard = document.getElementById('findingsCard');

    if (allFindings.length === 0) {
        dashboard.style.display = 'none';
        filtersCard.style.display = 'none';
        findingsCard.style.display = 'none';
        emptyState.style.display = 'block';
        return;
    }

    dashboard.style.display = 'grid';
    filtersCard.style.display = 'block';
    findingsCard.style.display = 'block';
    emptyState.style.display = 'none';

    const totalFindings = allFindings.length;
    const truePositives = allFindings.filter(f => !f.false_positive).length;
    const falsePositives = allFindings.filter(f => f.false_positive).length;
    const successRate = totalFindings > 0 
        ? Math.round((truePositives / totalFindings) * 100)
        : 0;

    document.getElementById('totalFindings').textContent = totalFindings;
    document.getElementById('truePositives').textContent = truePositives;
    document.getElementById('falsePositives').textContent = falsePositives;
    document.getElementById('successRate').textContent = successRate + '%';
}

function renderFindings() {
    const tbody = document.getElementById('findingsTableBody');
    tbody.innerHTML = '';

    if (filteredFindings.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center py-4 text-muted">
                    No findings match your filters
                </td>
            </tr>
        `;
        return;
    }

    filteredFindings.forEach((finding, index) => {
        const row = document.createElement('tr');
        const statusClass = finding.false_positive ? 'status-fp' : 'status-tp';
        const statusIcon = finding.false_positive ? '✗' : '✓';
        const statusText = finding.false_positive ? 'False Positive' : 'True Positive';
        
        row.innerHTML = `
            <td>
                <div class="status-indicator ${statusClass}" title="${statusText}">
                    ${statusIcon}
                </div>
            </td>
            <td>
                <small class="text-muted">${escapeHtml(truncateUrl(finding.url))}</small>
            </td>
            <td><code>${escapeHtml(finding.parameter || 'N/A')}</code></td>
            <td>
                <span class="badge bg-secondary">${escapeHtml(finding.method)}</span>
            </td>
            <td>
                <span class="badge bg-info">${escapeHtml(finding.confidence)}</span>
            </td>
            <td>
                <small class="verdict-text" title="${escapeHtml(finding.verdict)}">
                    ${escapeHtml(finding.verdict)}
                </small>
            </td>
            <td>
                <button class="btn btn-primary btn-sm btn-action" onclick="showDetails(${index})">
                    <i class="fas fa-eye"></i> Details
                </button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

function showDetails(index) {
    const finding = filteredFindings[index];
    const body = document.getElementById('detailModalBody');
    
    const statusBadge = finding.false_positive 
        ? '<span class="badge bg-warning">False Positive</span>'
        : '<span class="badge bg-danger">True Positive</span>';

    let html = `
        <div class="mb-3">
            <h6>Status ${statusBadge}</h6>
        </div>

        <div class="row mb-3">
            <div class="col-md-6">
                <strong>URL:</strong>
                <div class="text-break small">${escapeHtml(finding.url)}</div>
            </div>
            <div class="col-md-6">
                <strong>Parameter:</strong>
                <div><code>${escapeHtml(finding.parameter || 'N/A')}</code></div>
            </div>
        </div>

        <div class="row mb-3">
            <div class="col-md-4">
                <strong>Method:</strong>
                <div><span class="badge bg-secondary">${escapeHtml(finding.method)}</span></div>
            </div>
            <div class="col-md-4">
                <strong>Confidence:</strong>
                <div><span class="badge bg-info">${escapeHtml(finding.confidence)}</span></div>
            </div>
            <div class="col-md-4">
                <strong>False Positive:</strong>
                <div>${finding.false_positive ? 'Yes' : 'No'}</div>
            </div>
        </div>

        <hr>

        <div class="mb-3">
            <strong>Verdict:</strong>
            <div class="alert alert-info mb-0">${escapeHtml(finding.verdict)}</div>
        </div>

        <hr>

        <h6>Test Steps:</h6>
        <div id="testStepsContainer">
    `;

    finding.test_steps.forEach((step, stepIndex) => {
        html += renderTestStep(step, stepIndex);
    });

    html += `
        </div>
    `;

    body.innerHTML = html;
    modal.show();
}

function renderTestStep(step, stepIndex) {
    const headersHtml = (headers) => {
        return Object.entries(headers)
            .map(([key, value]) => `<dt>${escapeHtml(key)}</dt><dd>${escapeHtml(value)}</dd>`)
            .join('');
    };

    return `
        <div class="test-step">
            <div class="test-step-title">
                Step ${stepIndex + 1}: ${escapeHtml(step.step_name)}
            </div>
            
            <div class="mb-2">
                <strong>Payload:</strong>
                <div class="payload-text">${escapeHtml(step.payload)}</div>
            </div>

            <div class="mb-2">
                <strong>Result:</strong>
                <div class="small">${escapeHtml(step.result)}</div>
            </div>

            ${step.request ? `
                <div class="mb-2">
                    <button class="btn btn-sm btn-outline-secondary" type="button" data-bs-toggle="collapse" data-bs-target="#req${stepIndex}">
                        <i class="fas fa-arrow-right"></i> Request
                    </button>
                    <div class="collapse mt-2" id="req${stepIndex}">
                        <div class="code-block">
                            <pre><strong>${escapeHtml(step.request.method)}</strong> ${escapeHtml(step.request.path)}

<strong>Headers:</strong>
${Object.entries(step.request.headers)
    .map(([k, v]) => `${escapeHtml(k)}: ${escapeHtml(v)}`)
    .join('\n')}

<strong>Body:</strong>
${escapeHtml(step.request.body || '(empty)')}</pre>
                        </div>
                    </div>
                </div>
            ` : ''}

            ${step.response ? `
                <div class="mb-2">
                    <button class="btn btn-sm btn-outline-secondary" type="button" data-bs-toggle="collapse" data-bs-target="#res${stepIndex}">
                        <i class="fas fa-arrow-left"></i> Response
                    </button>
                    <div class="collapse mt-2" id="res${stepIndex}">
                        <div class="code-block">
                            <pre><strong>HTTP/1.1 ${escapeHtml(step.response.status_code)}</strong> ${escapeHtml(step.response.reason)}

<strong>Headers:</strong>
${Object.entries(step.response.headers)
    .map(([k, v]) => `${escapeHtml(k)}: ${escapeHtml(v)}`)
    .join('\n')}

<strong>Body:</strong>
${escapeHtml(step.response.body || '(empty)')}</pre>
                        </div>
                    </div>
                </div>
            ` : ''}
        </div>
    `;
}

function applyFilters() {
    const searchUrl = document.getElementById('searchUrl').value.toLowerCase();
    const filterStatus = document.getElementById('filterStatus').value;
    const filterMethod = document.getElementById('filterMethod').value;
    const filterConfidence = document.getElementById('filterConfidence').value;

    filteredFindings = allFindings.filter(finding => {
        const urlMatch = finding.url.toLowerCase().includes(searchUrl);
        const statusMatch = !filterStatus || 
            (filterStatus === 'true_positive' && !finding.false_positive) ||
            (filterStatus === 'false_positive' && finding.false_positive);
        const methodMatch = !filterMethod || finding.method === filterMethod;
        const confidenceMatch = !filterConfidence || finding.confidence.toLowerCase() === filterConfidence.toLowerCase();

        return urlMatch && statusMatch && methodMatch && confidenceMatch;
    });

    renderFindings();
}

function resetFilters() {
    document.getElementById('searchUrl').value = '';
    document.getElementById('filterStatus').value = '';
    document.getElementById('filterMethod').value = '';
    document.getElementById('filterConfidence').value = '';
    filteredFindings = [...allFindings];
    renderFindings();
}

function exportResults() {
    const dataToExport = filteredFindings.length > 0 ? filteredFindings : allFindings;
    const jsonString = JSON.stringify(dataToExport, null, 2);
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sqli-fp-results-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
}

function truncateUrl(url) {
    return url.length > 50 ? url.substring(0, 50) + '...' : url;
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return String(text).replace(/[&<>"']/g, m => map[m]);
}

// Event Listeners
document.getElementById('searchUrl').addEventListener('input', applyFilters);
document.getElementById('filterStatus').addEventListener('change', applyFilters);
document.getElementById('filterMethod').addEventListener('change', applyFilters);
document.getElementById('filterConfidence').addEventListener('change', applyFilters);
