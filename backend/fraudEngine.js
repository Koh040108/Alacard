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

/**
 * Main Risk Analysis Function
 * @param {Object} db - Database instance
 * @param {string} tokenHash - Token identifier
 * @param {Object} currentLocation - { state, city }
 * @returns {Object} { score: 0-100, reasons: [], level: 'SAFE'|'WARN'|'CRITICAL' }
 */
async function analyzeRisk(db, tokenHash, currentLocation) {
    let riskScore = 0;
    let reasons = [];

    // 1. Get History
    const history = await db.all(
        'SELECT * FROM audit_logs WHERE token_hash = ? ORDER BY audit_id DESC LIMIT 20',
        [tokenHash]
    );

    // If no history, it's a first-time use (Low Risk but flagged as New)
    if (history.length === 0) {
        return { score: 10, reasons: ["New Device/First Use"], level: 'SAFE' };
    }

    const lastLog = history[0];
    const lastTime = new Date(lastLog.timestamp).getTime();
    const currentTime = Date.now();
    const timeDiffHours = (currentTime - lastTime) / (1000 * 60 * 60);

    // Parse Locations
    const currCoords = LOCATION_MAP[currentLocation.state];
    let lastLocationObj = null;
    try {
        lastLocationObj = JSON.parse(lastLog.location);
    } catch (e) {
        lastLocationObj = { state: 'Unknown' };
    }

    // If we can map the coords, do physics checks
    if (currCoords && lastLocationObj && LOCATION_MAP[lastLocationObj.state]) {
        const lastCoords = LOCATION_MAP[lastLocationObj.state];

        // DISTANCE Check (in meters, convert to km)
        const distanceKm = geolib.getDistance(lastCoords, currCoords) / 1000;

        // VELOCITY Check
        if (distanceKm > 50 && timeDiffHours > 0.01) { // Ignore small jitters
            const velocity = distanceKm / timeDiffHours;

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
                    return LOCATION_MAP[l.state];
                } catch (e) { return null; }
            })
            .filter(p => p !== null);

        if (points.length >= 3) {
            const center = geolib.getCenter(points);
            // Distance from "Home/Normal" Center
            const distFromCenter = geolib.getDistance(center, currCoords) / 1000;

            // If new location is > 300km from usual center, slight risk
            if (distFromCenter > 300 && distanceKm > 100) {
                riskScore += 30;
                reasons.push(`Location Anomaly: ${Math.round(distFromCenter)}km from usual zone.`);
            }
        }
    }

    // FREQUENCY Check
    // If < 1 min since last tx
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
