// JavaScript for SARiMF Dashboard

let threatScanned = false;
let dreadEvaluated = false;

// Threat Scanner Logic
function runScanner() {
    const category = document.getElementById('strideCategory').value;
    const results = document.getElementById('scannerResults');
    results.innerHTML = '';

    const threats = {
        "Spoofing": "Potential impersonation detected.",
        "Tampering": "Data integrity risks identified.",
        "Repudiation": "No reliable logging mechanism found.",
        "Information Disclosure": "Sensitive data exposed.",
        "Denial of Service": "System vulnerable to high traffic.",
        "Elevation of Privilege": "Privilege escalation paths detected."
    };

    if (threats[category]) {
        const li = document.createElement('li');
        li.textContent = threats[category];
        results.appendChild(li);
        threatScanned = true;
    }
}

// DREAD Evaluator Logic
function evaluateDREAD() {
    const damage = parseInt(document.getElementById('damage').value) || 0;
    const repro = parseInt(document.getElementById('repro').value) || 0;
    const exploit = parseInt(document.getElementById('exploit').value) || 0;
    const affected = parseInt(document.getElementById('affected').value) || 0;
    const discover = parseInt(document.getElementById('discover').value) || 0;

    const score = (damage + repro + exploit + affected + discover) / 5;
    document.getElementById('dreadScore').textContent = `Risk Score: ${score.toFixed(2)}`;

    if (threatScanned) {
        dreadEvaluated = true;
    }
}

// Mitigation Recommender Logic
function recommendMitigations() {
    const results = document.getElementById('mitigationResults');
    results.innerHTML = '';

    if (!threatScanned || !dreadEvaluated) {
        results.innerHTML = '<li>Please complete Threat Scanner and DREAD Evaluator first.</li>';
        return;
    }

    const mitigations = [
        "Implement multi-factor authentication.",
        "Use secure hashing algorithms for data integrity.",
        "Ensure proper logging for non-repudiation.",
        "Encrypt sensitive data in transit and at rest.",
        "Deploy rate-limiting mechanisms to prevent DoS attacks.",
        "Restrict user privileges to the minimum required."
    ];

    mitigations.forEach(mitigation => {
        const li = document.createElement('li');
        li.textContent = mitigation;
        results.appendChild(li);
    });
}

// Interactive Dashboard Logic
function showDashboard() {
    if (!threatScanned || !dreadEvaluated) {
        alert("Please complete Threat Scanner and DREAD Evaluator first.");
        return;
    }

    const ctx = document.getElementById('riskChart').getContext('2d');

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure', 'DoS', 'EoP'],
            datasets: [{
                label: 'Risk Levels',
                data: [7, 8, 6, 9, 5, 8],
                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                borderColor: 'rgba(75, 192, 192, 1)',
                borderWidth: 1
            }]
        },
        options: {
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

// AI Analyzer Logic
function analyzeWithAI() {
    const results = document.getElementById('aiResults');
    results.textContent = "AI Insights: High risk of privilege escalation in the current configuration.";
}

// Vulnerability Database Search Logic
function searchVulnerabilities() {
    const keyword = document.getElementById('vulnerabilitySearch').value.toLowerCase();
    const results = document.getElementById('vulnerabilityResults');
    results.innerHTML = '';

    const database = {
        "spoofing": "CVE-2023-12345: Improper authentication.",
        "tampering": "CVE-2022-23456: Data manipulation vulnerability.",
        "repudiation": "CVE-2021-34567: Insufficient logging.",
        "information disclosure": "CVE-2020-45678: Data exposure in API.",
        "denial of service": "CVE-2019-56789: High traffic crash vulnerability.",
        "elevation of privilege": "CVE-2018-67890: Privilege escalation exploit."
    };

    if (database[keyword]) {
        const li = document.createElement('li');
        li.textContent = database[keyword];
        results.appendChild(li);
    } else {
        const li = document.createElement('li');
        li.textContent = "No vulnerabilities found for the entered keyword.";
        results.appendChild(li);
    }
}
