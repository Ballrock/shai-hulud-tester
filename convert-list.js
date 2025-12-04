const fs = require('fs');
const path = require('path');
const https = require('https');

// DataDog CSV URL
const CSV_URL = 'https://raw.githubusercontent.com/DataDog/indicators-of-compromise/main/shai-hulud-2.0/consolidated_iocs.csv';

// Create tmp folder if it doesn't exist
const tmpDir = path.join(__dirname, 'tmp');
if (!fs.existsSync(tmpDir)) {
    fs.mkdirSync(tmpDir);
}

console.log('📥 Downloading CSV file from DataDog...');

// Download CSV file to tmp/
const tmpCsvPath = path.join(tmpDir, 'datadog-iocs.csv');

https.get(CSV_URL, (response) => {
    let csvContent = '';
    
    response.on('data', (chunk) => {
        csvContent += chunk;
    });
    
    response.on('end', () => {
        console.log('✅ Download complete!');
        
        // Save to tmp/
        fs.writeFileSync(tmpCsvPath, csvContent, 'utf-8');
        
        processCSV(csvContent);
        
        // Clean tmp folder
        console.log('🧹 Cleaning tmp/ folder...');
        fs.rmSync(tmpDir, { recursive: true, force: true });
        console.log('✨ Cleanup complete!');
    });
}).on('error', (err) => {
    console.error('❌ Download error:', err.message);
    
    // Clean on error
    if (fs.existsSync(tmpDir)) {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
    process.exit(1);
});

function processCSV(csvContent) {

    // Parse CSV and extract packages with their compromised versions
    const lines = csvContent.split('\n');
    const packages = [];

    for (let i = 1; i < lines.length; i++) { // Skip header
        const line = lines[i].trim();
        if (!line) continue;
        
        // Parse CSV line (format: package_name,package_versions,"sources")
        // Split by comma but respect quotes
        const parts = [];
        let current = '';
        let inQuotes = false;
        
        for (let char of line) {
            if (char === '"') {
                inQuotes = !inQuotes;
            } else if (char === ',' && !inQuotes) {
                parts.push(current.trim());
                current = '';
            } else {
                current += char;
            }
        }
        parts.push(current.trim());
        
        if (parts.length >= 2) {
            const packageName = parts[0];
            const versionsString = parts[1];
            
            // Keep versions grouped by package
            const versions = versionsString.split(',').map(v => v.trim()).filter(v => v);
            
            packages.push({
                name: packageName,
                compromisedVersions: versions
            });
        }
    }

    // Create JSON object
    const jsonOutput = {
        "attackName": "Shai Hulud 2.0",
        "lastUpdate": new Date().toISOString().split('T')[0],
        "source": "https://github.com/DataDog/indicators-of-compromise/blob/main/shai-hulud-2.0/consolidated_iocs.csv",
        "compromisedPackages": packages
    };

    // Write to data/compromised-packages.json
    const dataDir = path.join(__dirname, 'data');
    if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir);
    }
    
    const outputPath = path.join(dataDir, 'compromised-packages.json');
    fs.writeFileSync(outputPath, JSON.stringify(jsonOutput, null, 2), 'utf-8');

    console.log(`✅ Conversion complete!`);
    console.log(`📦 ${packages.length} compromised packages detected`);
    console.log(`📝 File generated: ${outputPath}`);
}
