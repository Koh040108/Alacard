const geolib = require('geolib');

// approximate coordinates for Malaysian states/cities
const LOCATION_MAP = {
    'Selangor': { latitude: 3.107, longitude: 101.606 },
    'Perak': { latitude: 4.597, longitude: 101.090 },
    'Penang': { latitude: 5.414, longitude: 100.311 },
    'Johor': { latitude: 1.485, longitude: 103.761 },
    'Sabah': { latitude: 5.980, longitude: 116.073 },
    'Sarawak': { latitude: 1.553, longitude: 110.359 }
};

// Heuristics
const MAX_VELOCITY_KMH = 800; // Plane speed
const FREQUENCY_LIMIT_MINS = 5; // Min minutes between rapid hops

// Helper: Get coords for terminal location
const getTerminalCoords = (locName) => {
    return LOCATION_MAP[locName] || null;
}

/**
 * Main Risk Analysis Function
 * @param {Object} db - Database instance
 * @param {string} tokenHash - Token identifier
 * @param {Object} terminalLocation - { state, city } (From Terminal)
 * @param {Object} walletLocation - { lat, lng } (From Phone GPS) or null
 * @returns {Object} { score: 0-100, reasons: [], level: 'SAFE'|'WARN'|'CRITICAL' }
 */
async function analyzeRisk(db, tokenHash, terminalLocation, walletLocation) {
    let riskScore = 0;
    let reasons = [];

    // --- RULE 0: PROXIMITY CHECK (Relay Attack Prevention) ---
    let terminalCoords = null;
    // Check if terminal provided raw GPS coordinates (Real Location mode)
    if (terminalLocation.latitude && terminalLocation.longitude) {
        terminalCoords = { latitude: terminalLocation.latitude, longitude: terminalLocation.longitude };
    } else {
        // Fallback to State Lookup (Simulation/Static mode)
        terminalCoords = LOCATION_MAP[terminalLocation.state];
    }

    if (walletLocation && terminalCoords) {
        // Calculate distance between Phone (Wallet) and Terminal (Kiosk)
        const distMeters = geolib.getDistance(
            { latitude: walletLocation.lat, longitude: walletLocation.lng },
            terminalCoords
        );
        const distKm = distMeters / 1000;

        console.log(`[AI Proximity] Wallet vs Terminal: ${distKm.toFixed(2)} km`);

        if (distKm > 100) {
            riskScore += 90;
            reasons.push(`Relay Attack Detected: Phone is ${distKm.toFixed(0)}km away from Terminal!`);
        } else if (distKm > 5) {
            riskScore += 50;
            reasons.push(`Proximity Mismatch: Phone is ${distKm.toFixed(1)}km away from Terminal.`);
        }
    } else {
        // Missing Location Data
        if (!walletLocation) {
            // Risk is low because user might just have GPS off, but worth noting
            riskScore += 10;
            reasons.push("Wallet Location Missing (GPS Off?)");
        }
    }


    // 1. Get History (Using Prisma instead of SQLite)
    const history = await db.auditLog.findMany({
        where: { token_hash: tokenHash },
        orderBy: { audit_id: 'desc' },
        take: 20
    });

    // If no history, it's a first-time use (Low Risk but flagged as New)
    if (history.length === 0) {
        // If we already have high risk from proximity, don't overwrite it, just return
        const finalScore = Math.max(riskScore, 10);
        const finalReasons = [...reasons, "New Device/First Use"];
        return {
            score: finalScore,
            reasons: finalReasons,
            level: finalScore > 60 ? 'CRITICAL' : finalScore > 20 ? 'WARN' : 'SAFE'
        };
    }

    // 2. Frequency Check Baseline (Last Activity)
    const lastLog = history[0];
    const lastActivityTime = new Date(lastLog.timestamp).getTime();
    const currentTime = Date.now();
    const timeDiffHours = (currentTime - lastActivityTime) / (1000 * 60 * 60);

    // 3. Find Last Valid Physical Location for Impossible Travel
    let lastValidLog = null;
    let lastCoords = null;
    let lastValidTime = null;

    for (const log of history) {
        try {
            const locObj = JSON.parse(log.location);
            if (locObj && locObj.state && LOCATION_MAP[locObj.state]) {
                lastValidLog = log;
                lastCoords = LOCATION_MAP[locObj.state];
                lastValidTime = new Date(log.timestamp).getTime();
                break; // Found the most recent valid physical log
            }
        } catch (e) {
            // Ignore logs with non-JSON location (e.g. "My Profile")
        }
    }

    // If we can map the coords, do physics checks (Impossible Travel)
    if (terminalCoords && lastValidLog && lastCoords) {
        const travelTimeDiff = (currentTime - lastValidTime) / (1000 * 60 * 60);

        // DISTANCE Check (in meters, convert to km)
        const distanceKm = geolib.getDistance(lastCoords, terminalCoords) / 1000;

        // VELOCITY Check
        if (distanceKm > 50 && travelTimeDiff > 0.01) { // Ignore small jitters
            const velocity = distanceKm / travelTimeDiff;

            if (velocity > MAX_VELOCITY_KMH) {
                riskScore += 80; // Critical impact
                reasons.push(`Impossible Travel: ${Math.round(velocity)} km/h detected.`);
            }
        }

        // CLUSTERING / ANOMALY Check (Simple Centroid)
        // Gather all valid historical points
        const points = history
            .map(h => {
                try {
                    const l = JSON.parse(h.location);
                    if (!l || !l.state) return null;
                    return LOCATION_MAP[l.state] || null;
                } catch (e) { return null; }
            })
            .filter(p => p !== null);

        if (points.length >= 3) {
            const center = geolib.getCenter(points);
            // Distance from "Home/Normal" Center
            const distFromCenter = geolib.getDistance(center, terminalCoords) / 1000;

            // If new location is > 300km from usual center, slight risk
            if (distFromCenter > 300 && distanceKm > 100) {
                riskScore += 30;
                reasons.push(`Location Anomaly: ${Math.round(distFromCenter)}km from usual zone.`);
            }
        }
    }

    // FREQUENCY Check
    // If < 1 min since last tx (ANY tx)
    if (timeDiffHours < (1 / 60)) {
        riskScore += 20;
        reasons.push("High Frequency Activity");
    }

    // Cap Score
    riskScore = Math.min(riskScore, 100);

    // Determine Level
    let level = 'SAFE';
    if (riskScore > 60) level = 'CRITICAL';
    else if (riskScore > 20) level = 'WARN';

    if (riskScore === 0) reasons.push("Normal Behavior Profile");

    return {
        score: riskScore,
        reasons: reasons,
        level: level,
        details: {
            distance_from_last: 'Calculation needed', // simplified for now
            velocity: 'Calculation needed'
        }
    };
}

module.exports = { analyzeRisk };