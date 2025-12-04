const { test, describe } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

// Load data file
const dataPath = path.join(__dirname, '../../data/compromised-packages.json');
let compromisedData;

try {
    compromisedData = JSON.parse(fs.readFileSync(dataPath, 'utf-8'));
} catch (error) {
    console.error('Error: The file data/compromised-packages.json does not exist.');
    console.error('Run: node convert-list.js');
    process.exit(1);
}

// Utility functions (copied from app.js)
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

function checkPackage(packageName, version) {
    const compromisedPkg = compromisedData.compromisedPackages.find(
        pkg => pkg.name === packageName
    );
    
    if (!compromisedPkg) return null;
    
    const exactMatch = compromisedPkg.compromisedVersions.includes(version);
    
    if (exactMatch) {
        return {
            severity: 'critical',
            exactMatch: true,
            compromisedVersions: compromisedPkg.compromisedVersions
        };
    }
    
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
            exactMatch: false,
            compromisedVersions: compromisedPkg.compromisedVersions
        };
    }
    
    return {
        severity: 'warning',
        exactMatch: false,
        compromisedVersions: compromisedPkg.compromisedVersions
    };
}

describe('Data Validation', () => {
    test('compromised-packages.json should exist and be valid', () => {
        assert.ok(compromisedData, 'File should be loaded');
        assert.ok(compromisedData.attackName, 'attackName should be present');
        assert.ok(compromisedData.lastUpdate, 'lastUpdate should be present');
        assert.ok(Array.isArray(compromisedData.compromisedPackages), 'compromisedPackages should be an array');
        assert.ok(compromisedData.compromisedPackages.length > 0, 'There should be at least 1 compromised package');
    });

    test('each package should have a name and versions', () => {
        compromisedData.compromisedPackages.forEach((pkg, index) => {
            assert.ok(pkg.name, `Package ${index} should have a name`);
            assert.ok(Array.isArray(pkg.compromisedVersions), `Package ${pkg.name} should have a versions array`);
            assert.ok(pkg.compromisedVersions.length > 0, `Package ${pkg.name} should have at least one compromised version`);
        });
    });
});

describe('Detection - Exact Match (Critical)', () => {
    test('should detect a package with exact compromised version', () => {
        // Use first package from the list
        const testPkg = compromisedData.compromisedPackages[0];
        const testVersion = testPkg.compromisedVersions[0];
        
        const result = checkPackage(testPkg.name, testVersion);
        
        assert.ok(result, 'A result should be returned');
        assert.strictEqual(result.severity, 'critical', 'Severity should be "critical"');
        assert.strictEqual(result.exactMatch, true, 'exactMatch should be true');
    });

    test('should detect @asyncapi/parser@3.4.1 (if present)', () => {
        const pkg = compromisedData.compromisedPackages.find(p => p.name === '@asyncapi/parser');
        if (pkg && pkg.compromisedVersions.includes('3.4.1')) {
            const result = checkPackage('@asyncapi/parser', '3.4.1');
            assert.strictEqual(result.severity, 'critical');
            assert.strictEqual(result.exactMatch, true);
        }
    });
});

describe('Detection - Higher Version (High)', () => {
    test('should detect a higher version of a compromised package', () => {
        const testPkg = compromisedData.compromisedPackages[0];
        const compromisedVersion = testPkg.compromisedVersions[0];
        
        // Create a higher version
        const parts = compromisedVersion.split('.');
        parts[parts.length - 1] = String(parseInt(parts[parts.length - 1]) + 10);
        const higherVersion = parts.join('.');
        
        const result = checkPackage(testPkg.name, higherVersion);
        
        assert.ok(result, 'A result should be returned');
        assert.strictEqual(result.severity, 'high', 'Severity should be "high"');
        assert.strictEqual(result.exactMatch, false, 'exactMatch should be false');
    });
});

describe('Detection - Different Version (Warning)', () => {
    test('should detect a different version of a compromised package', () => {
        const testPkg = compromisedData.compromisedPackages[0];
        
        // Completely different version
        const differentVersion = '0.0.1';
        
        const result = checkPackage(testPkg.name, differentVersion);
        
        assert.ok(result, 'A result should be returned');
        // Can be 'warning' or 'high' depending on comparison
        assert.ok(['warning', 'high'].includes(result.severity), 'Severity should be "warning" or "high"');
    });
});

describe('Detection - Safe Packages', () => {
    test('should not detect a non-compromised package', () => {
        const result = checkPackage('express', '4.18.2');
        assert.strictEqual(result, null, 'No result should be returned for a safe package');
    });

    test('should not detect react as compromised', () => {
        const result = checkPackage('react', '18.2.0');
        assert.strictEqual(result, null);
    });
});

describe('Version Comparison', () => {
    test('should correctly compare semantic versions', () => {
        assert.strictEqual(compareVersions('1.0.0', '1.0.0'), 0, '1.0.0 = 1.0.0');
        assert.strictEqual(compareVersions('1.0.1', '1.0.0'), 1, '1.0.1 > 1.0.0');
        assert.strictEqual(compareVersions('1.0.0', '1.0.1'), -1, '1.0.0 < 1.0.1');
        assert.strictEqual(compareVersions('2.0.0', '1.9.9'), 1, '2.0.0 > 1.9.9');
        assert.strictEqual(compareVersions('1.2.3', '1.2.3'), 0, '1.2.3 = 1.2.3');
    });
});
