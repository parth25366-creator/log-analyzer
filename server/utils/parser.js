// Log Parser — detects suspicious patterns in server logs

const parseLine = (line) => {
  const regex = /^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\S+)/;
  const match = line.match(regex);
  if (!match) return null;
  return {
    ip: match[1],
    date: match[2],
    method: match[3],
    path: match[4],
    status: parseInt(match[5]),
    bytes: match[6]
  };
};

// brute force — IP with many 401/403 responses
const detectBruteForce = (entries, threshold = 10) => {
  const failMap = {};
  entries.forEach(e => {
    if (e.status === 401 || e.status === 403) {
      failMap[e.ip] = (failMap[e.ip] || 0) + 1;
    }
  });
  return Object.entries(failMap)
    .filter(([, count]) => count >= threshold)
    .map(([ip, count]) => ({ ip, count, type: 'Brute Force' }));
};

// high volume — IP sending too many requests
const detectHighVolume = (entries, threshold = 100) => {
  const ipMap = {};
  entries.forEach(e => { ipMap[e.ip] = (ipMap[e.ip] || 0) + 1; });
  return Object.entries(ipMap)
    .filter(([, count]) => count >= threshold)
    .map(([ip, count]) => ({ ip, count, type: 'High Volume' }));
};

// scanner detection — IP hitting many 404s (path scanning)
const detectScanner = (entries, threshold = 20) => {
  const scanMap = {};
  entries.forEach(e => {
    if (e.status === 404) {
      scanMap[e.ip] = (scanMap[e.ip] || 0) + 1;
    }
  });
  return Object.entries(scanMap)
    .filter(([, count]) => count >= threshold)
    .map(([ip, count]) => ({ ip, count, type: 'Scanner / Path Enumeration' }));
};

// summary stats
const getSummary = (entries) => ({
  totalRequests: entries.length,
  uniqueIPs: new Set(entries.map(e => e.ip)).size,
  totalErrors: entries.filter(e => e.status >= 400).length,
  top5IPs: Object.entries(
    entries.reduce((acc, e) => { acc[e.ip] = (acc[e.ip] || 0) + 1; return acc; }, {})
  ).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([ip, count]) => ({ ip, count }))
});

module.exports = { parseLine, detectBruteForce, detectHighVolume, detectScanner, getSummary };
