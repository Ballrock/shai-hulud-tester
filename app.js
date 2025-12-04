// Global variables
let compromisedPackagesData = null;

// Load data on startup
async function loadCompromisedPackages() {
    try {
        const response = await fetch('data/compromised-packages.json');
        compromisedPackagesData = await response.json();
        updateInfoSection();
    } catch (error) {
        console.error('Error loading compromised packages:', error);
        document.getElementById('compromisedCount').textContent = 'Loading error';
    }
}

// Update info section
function updateInfoSection() {
    if (!compromisedPackagesData) return;
    
    const count = compromisedPackagesData.compromisedPackages.length;
    const lastUpdate = compromisedPackagesData.lastUpdate;
    const attackName = compromisedPackagesData.attackName || 'Unknown attack';
    
    document.getElementById('compromisedCount').textContent = 
        `${count} compromised packages - ${attackName}`;
    document.getElementById('lastUpdate').textContent = 
        `Last update: ${formatDate(lastUpdate)}`;
    document.getElementById('footerDate').textContent = 
        `Last data update: ${formatDate(lastUpdate)}`;
}

// Format date
function formatDate(dateString) {
    const options = { year: 'numeric', month: 'long', day: 'numeric' };
    return new Date(dateString).toLocaleDateString('en-US', options);
}

// Handle uploaded file
document.getElementById('fileInput').addEventListener('change', async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    
    try {
        const content = await file.text();
        const packageLock = JSON.parse(content);
        analyzePackageLock(packageLock);
    } catch (error) {
        alert('Error reading file. Make sure it is a valid package-lock.json file.');
        console.error(error);
    }
});

// Handle analyze button for pasted text
document.getElementById('analyzeButton').addEventListener('click', () => {
    const pastedContent = document.getElementById('pasteArea').value.trim();
    
    if (!pastedContent) {
        alert('Please paste your package-lock.json content in the text area.');
        return;
    }
    
    try {
        const packageLock = JSON.parse(pastedContent);
        analyzePackageLock(packageLock);
    } catch (error) {
        alert('Error analyzing content. Make sure it is valid package-lock.json JSON.');
        console.error(error);
    }
});

// Drag and drop
const uploadBox = document.querySelector('.upload-box');

uploadBox.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadBox.classList.add('drag-over');
});

uploadBox.addEventListener('dragleave', () => {
    uploadBox.classList.remove('drag-over');
});

uploadBox.addEventListener('drop', async (e) => {
    e.preventDefault();
    uploadBox.classList.remove('drag-over');
    
    const file = e.dataTransfer.files[0];
    if (file && file.name.includes('package-lock.json')) {
        try {
            const content = await file.text();
            const packageLock = JSON.parse(content);
            analyzePackageLock(packageLock);
        } catch (error) {
            alert('Error reading file.');
            console.error(error);
        }
    } else {
        alert('Please drop a valid package-lock.json file.');
    }
});

// Analyze package-lock.json
function analyzePackageLock(packageLock) {
    if (!compromisedPackagesData) {
        alert('Compromised packages data is not loaded yet.');
        return;
    }
    
    const results = {
        safe: 0,
        warnings: 0,
        threats: [],
        allPackages: []
    };
    
    // Extract dependencies (npm format v1, v2, v3)
    const dependencies = extractDependencies(packageLock);
    
    // Analyze each dependency
    dependencies.forEach(dep => {
        const threat = checkPackage(dep.name, dep.version);
        
        if (threat) {
            results.threats.push({
                ...dep,
                threat: threat
            });
        } else {
            results.safe++;
        }
        
        results.allPackages.push(dep);
    });
    
    displayResults(results);
}

// Extract dependencies from package-lock
function extractDependencies(packageLock) {
    const dependencies = [];
    
    // npm format v2 and v3 (lockfileVersion 2 or 3)
    if (packageLock.packages) {
        Object.entries(packageLock.packages).forEach(([path, pkg]) => {
            if (path === '') return; // Skip root
            
            const name = pkg.name || path.replace(/^node_modules\//, '');
            const version = pkg.version;
            
            if (name && version) {
                dependencies.push({ name, version, path });
            }
        });
    }
    
    // npm format v1 (lockfileVersion 1)
    if (packageLock.dependencies) {
        extractDependenciesRecursive(packageLock.dependencies, dependencies);
    }
    
    return dependencies;
}

// Recursive extraction for npm v1
function extractDependenciesRecursive(deps, result, prefix = '') {
    Object.entries(deps).forEach(([name, info]) => {
        result.push({
            name: name,
            version: info.version,
            path: prefix + name
        });
        
        if (info.dependencies) {
            extractDependenciesRecursive(info.dependencies, result, prefix + name + ' > ');
        }
    });
}

// Semantic version comparison
function compareVersions(v1, v2) {
    const parts1 = v1.split('.').map(Number);
    const parts2 = v2.split('.').map(Number);
    
    for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
        const p1 = parts1[i] || 0;
        const p2 = parts2[i] || 0;
        
        if (p1 > p2) return 1;
        if (p1 < p2) return -1;
    }
    return 0;
}

// Check a package
function checkPackage(packageName, version) {
    // Search for package in compromised list
    const compromisedPkg = compromisedPackagesData.compromisedPackages.find(
        pkg => pkg.name === packageName
    );
    
    if (!compromisedPkg) return null;
    
    // Check if exact version is compromised (CRITICAL)
    const exactMatch = compromisedPkg.compromisedVersions.includes(version);
    
    if (exactMatch) {
        return {
            severity: 'critical',
            description: `🚨 CRITICAL - Exact compromised version detected in ${compromisedPackagesData.attackName} attack`,
            compromisedVersions: compromisedPkg.compromisedVersions,
            installedVersion: version,
            exactMatch: true
        };
    }
    
    // Check if installed version is higher than compromised versions (HIGH)
    const isHigherVersion = compromisedPkg.compromisedVersions.some(compVer => {
        try {
            return compareVersions(version, compVer) > 0;
        } catch (e) {
            return false;
        }
    });
    
    if (isHigherVersion) {
        return {
            severity: 'high',
            description: `⚠️ HIGH - This package has compromised versions. Your version is higher but stay vigilant.`,
            compromisedVersions: compromisedPkg.compromisedVersions,
            installedVersion: version,
            exactMatch: false
        };
    }
    
    // Different version but known compromised package
    return {
        severity: 'warning',
        description: `⚡ MEDIUM - Package known as compromised but your version differs.`,
        compromisedVersions: compromisedPkg.compromisedVersions,
        installedVersion: version,
        exactMatch: false
    };
}

// Display results
function displayResults(results) {
    const resultsSection = document.getElementById('resultsSection');
    const threatsContainer = document.getElementById('threatsContainer');
    const detailsContainer = document.getElementById('detailsContainer');
    
    // Update counters
    document.getElementById('safeCount').textContent = results.safe;
    document.getElementById('warningCount').textContent = 
        results.threats.filter(t => t.threat.severity === 'warning' || t.threat.severity === 'high').length;
    document.getElementById('dangerCount').textContent = 
        results.threats.filter(t => t.threat.severity === 'critical').length;
    
    // Display threats
    threatsContainer.innerHTML = '';
    
    if (results.threats.length === 0) {
        threatsContainer.innerHTML = `
            <div class="no-threats">
                <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                    <polyline points="22 4 12 14.01 9 11.01"></polyline>
                </svg>
                <h3>No threats detected</h3>
                <p>All your packages are safe according to our database.</p>
            </div>
        `;
    } else {
        results.threats.forEach(threat => {
            const threatCard = createThreatCard(threat);
            threatsContainer.appendChild(threatCard);
        });
    }
    
    // Display details
    const totalPackages = results.allPackages.length;
    detailsContainer.innerHTML = `
        <div class="details-summary">
            <h3>📊 Statistics</h3>
            <p>Total packages analyzed: <strong>${totalPackages}</strong></p>
            <p>Safe packages: <strong>${results.safe}</strong> (${((results.safe / totalPackages) * 100).toFixed(1)}%)</p>
            <p>Threats detected: <strong>${results.threats.length}</strong> (${((results.threats.length / totalPackages) * 100).toFixed(1)}%)</p>
        </div>
    `;
    
    resultsSection.style.display = 'block';
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Create a threat card
function createThreatCard(threat) {
    const card = document.createElement('div');
    card.className = `threat-card severity-${threat.threat.severity}`;
    
    const severityLabel = {
        'critical': '🔴 CRITICAL',
        'high': '🟠 HIGH',
        'warning': '🟡 MEDIUM'
    }[threat.threat.severity] || '⚠️ UNKNOWN';
    
    let detailsHtml = '';
    
    if (threat.threat.exactMatch) {
        detailsHtml = `
            <div class="threat-details critical-box">
                <p class="warning-text"><strong>🚨 CRITICAL ALERT - EXACT COMPROMISED VERSION</strong></p>
                <p><strong>Installed version:</strong> <code class="danger-code">${threat.threat.installedVersion}</code></p>
                <p><strong>Known compromised versions:</strong> ${threat.threat.compromisedVersions.join(', ')}</p>
                <p class="action-required"><strong>⚠️ IMMEDIATE ACTION REQUIRED - Remove this package now!</strong></p>
            </div>
        `;
    } else {
        detailsHtml = `
            <div class="threat-details">
                <p><strong>Installed version:</strong> <code>${threat.threat.installedVersion}</code></p>
                <p><strong>Known compromised versions:</strong> ${threat.threat.compromisedVersions.join(', ')}</p>
                ${threat.threat.severity === 'high' ? 
                    '<p class="warning-text"><strong>Your version is higher than compromised versions, but this package is malicious</strong></p>' :
                    '<p>Your version differs from listed compromised versions</p>'
                }
            </div>
        `;
    }
    
    card.innerHTML = `
        <div class="threat-header">
            <h3>${threat.name}</h3>
            <span class="severity-badge">${severityLabel}</span>
        </div>
        <div class="threat-body">
            <p class="threat-description">${threat.threat.description}</p>
            ${detailsHtml}
        </div>
        <div class="threat-actions">
            <button onclick="copyPackageName('${threat.name}')">Copy name</button>
            <button class="danger-btn" onclick="copyRemoveCommand('${threat.name}')">Copy removal command</button>
        </div>
    `;
    
    return card;
}

// Utility functions to copy to clipboard
function copyPackageName(name) {
    navigator.clipboard.writeText(name);
    showNotification('Package name copied!');
}

function copyRemoveCommand(name) {
    const command = `npm uninstall ${name}`;
    navigator.clipboard.writeText(command);
    showNotification('Removal command copied!');
}

function showNotification(message) {
    const notification = document.createElement('div');
    notification.className = 'notification';
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.classList.add('show');
    }, 10);
    
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }, 2000);
}

// Initialize
loadCompromisedPackages();
