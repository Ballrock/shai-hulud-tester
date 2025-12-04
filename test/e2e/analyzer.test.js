const { test, describe, before, after } = require('node:test');
const assert = require('node:assert');
const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const TEST_PORT = 8181;
const BASE_URL = `http://localhost:${TEST_PORT}`;
let server;

// Create a simple HTTP server for tests
before(async () => {
    const handler = require('http').createServer((req, res) => {
        const filePath = path.join(__dirname, '../..', req.url === '/' ? '/index.html' : req.url);
        
        if (fs.existsSync(filePath)) {
            const ext = path.extname(filePath);
            const contentType = {
                '.html': 'text/html',
                '.js': 'application/javascript',
                '.css': 'text/css',
                '.json': 'application/json'
            }[ext] || 'text/plain';
            
            res.writeHead(200, { 'Content-Type': contentType });
            res.end(fs.readFileSync(filePath));
        } else {
            res.writeHead(404);
            res.end('Not found');
        }
    });
    
    server = handler.listen(TEST_PORT);
    console.log(`Test server started on port ${TEST_PORT}`);
});

after(() => {
    if (server) {
        server.close();
        console.log('Test server stopped');
    }
});

describe('E2E - Page Loading', () => {
    test('main page should load without error', async () => {
        const response = await fetch(BASE_URL);
        assert.strictEqual(response.status, 200);
        const html = await response.text();
        assert.ok(html.includes('Package-Lock Security Analyzer'));
    });

    test('JS and CSS resources should be accessible', async () => {
        const jsResponse = await fetch(`${BASE_URL}/app.js`);
        assert.strictEqual(jsResponse.status, 200);
        
        const cssResponse = await fetch(`${BASE_URL}/styles.css`);
        assert.strictEqual(cssResponse.status, 200);
    });

    test('compromised data should be accessible', async () => {
        const response = await fetch(`${BASE_URL}/data/compromised-packages.json`);
        assert.strictEqual(response.status, 200);
        
        const data = await response.json();
        assert.ok(data.attackName);
        assert.ok(Array.isArray(data.compromisedPackages));
        assert.ok(data.compromisedPackages.length > 0);
    });
});

describe('E2E - Package Lock Analysis', () => {
    test('should detect a compromised package in package-lock.json', async () => {
        // Load data
        const compromisedData = await (await fetch(`${BASE_URL}/data/compromised-packages.json`)).json();
        
        // Load fixture with threat
        const packageLock = JSON.parse(
            fs.readFileSync(path.join(__dirname, '../fixtures/package-lock-with-threat.json'), 'utf-8')
        );
        
        // Extract dependencies
        const dependencies = [];
        if (packageLock.packages) {
            Object.entries(packageLock.packages).forEach(([pkgPath, pkg]) => {
                if (pkgPath === '') return;
                const name = pkg.name || pkgPath.replace(/^node_modules\//, '');
                const version = pkg.version;
                if (name && version) {
                    dependencies.push({ name, version });
                }
            });
        }
        
        // Vérifier la détection
        let threatsFound = 0;
        dependencies.forEach(dep => {
            const compromisedPkg = compromisedData.compromisedPackages.find(p => p.name === dep.name);
            if (compromisedPkg) {
                const exactMatch = compromisedPkg.compromisedVersions.includes(dep.version);
                if (exactMatch) {
                    threatsFound++;
                }
            }
        });
        
        assert.ok(threatsFound > 0, 'At least one threat should be detected');
    });

    test('should not detect threats in a safe package-lock.json', async () => {
        const compromisedData = await (await fetch(`${BASE_URL}/data/compromised-packages.json`)).json();
        
        const packageLock = JSON.parse(
            fs.readFileSync(path.join(__dirname, '../fixtures/package-lock-safe.json'), 'utf-8')
        );
        
        const dependencies = [];
        if (packageLock.packages) {
            Object.entries(packageLock.packages).forEach(([pkgPath, pkg]) => {
                if (pkgPath === '') return;
                const name = pkg.name || pkgPath.replace(/^node_modules\//, '');
                const version = pkg.version;
                if (name && version) {
                    dependencies.push({ name, version });
                }
            });
        }
        
        let threatsFound = 0;
        dependencies.forEach(dep => {
            const compromisedPkg = compromisedData.compromisedPackages.find(p => p.name === dep.name);
            if (compromisedPkg) {
                const exactMatch = compromisedPkg.compromisedVersions.includes(dep.version);
                if (exactMatch) {
                    threatsFound++;
                }
            }
        });
        
        assert.strictEqual(threatsFound, 0, 'No threats should be detected');
    });
});

describe('E2E - Data Statistics', () => {
    test('should have approximately 795 compromised packages', async () => {
        const response = await fetch(`${BASE_URL}/data/compromised-packages.json`);
        const data = await response.json();
        
        // Check that we have approximately 795 packages (with margin)
        assert.ok(data.compromisedPackages.length >= 700, 'At least 700 packages');
        assert.ok(data.compromisedPackages.length <= 900, 'No more than 900 packages');
    });

    test('data should have a recent update date', async () => {
        const response = await fetch(`${BASE_URL}/data/compromised-packages.json`);
        const data = await response.json();
        
        const lastUpdate = new Date(data.lastUpdate);
        const now = new Date();
        const daysDiff = (now - lastUpdate) / (1000 * 60 * 60 * 24);
        
        // Data should not be older than 7 days
        assert.ok(daysDiff <= 7, `Data is ${Math.floor(daysDiff)} days old`);
    });
});
