// Log Parser — supports Apache access logs and Apache error logs

// parse Apache access log line
// format: IP - - [date] "METHOD /path HTTP/1.1" status bytes
const parseAccessLine = (line) => {
  const regex = /^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\S+)/;
  const match = line.match(regex);
  if (!match) return null;
  return {
    type: 'access',
    ip: match[1],
    date: match[2],
    method: match[3],
    path: match[4],
    status: parseInt(match[5]),
    bytes: match[6]
  };
};

// parse Apache error log line
// format: [date] [level] message (optional: client IP)
const parseErrorLine = (line) => {
  const regex = /^\[([^\]]+)\] \[(\w+)\] (.+)/;
  const match = line.match(regex);
  if (!match) return null;

  const message = match[3];
  const level = match[2];

  // try to extract IP from message if present
  const ipMatch = message.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  const ip = ipMatch ? ipMatch[1] : null;

  return {
    type: 'error',
    date: match[1],
    level,
    message,
    ip,
    // map error levels to pseudo status codes for detection
    status: level === 'error' ? 500 : level === 'warn' ? 400 : 200
  };
};

// auto detect and parse any line
const parseLine = (line) => {
  // try access log format first
  const access = parseAccessLine(line);
  if (access) return access;
  // try error log format
  const error = parseErrorLine(line);
  if (error) return error;
  return null;
};

// brute force — IP with many 401/403 responses (access logs)
const detectBruteForce = (entries, threshold = 10) => {
  const failMap = {};
  entries.forEach(e => {
    if (e.ip && (e.status === 401 || e.status === 403)) {
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
  entries.forEach(e => {
    if (e.ip) ipMap[e.ip] = (ipMap[e.ip] || 0) + 1;
  });
  return Object.entries(ipMap)
    .filter(([, count]) => count >= threshold)
    .map(([ip, count]) => ({ ip, count, type: 'High Volume' }));
};

// scanner — IP hitting many 404s (path enumeration)
const detectScanner = (entries, threshold = 20) => {
  const scanMap = {};
  entries.forEach(e => {
    if (e.ip && e.status === 404) {
      scanMap[e.ip] = (scanMap[e.ip] || 0) + 1;
    }
  });
  return Object.entries(scanMap)
    .filter(([, count]) => count >= threshold)
    .map(([ip, count]) => ({ ip, count, type: 'Scanner / Path Enumeration' }));
};

// repeated errors — for error logs, detect IPs with many errors
const detectRepeatedErrors = (entries, threshold = 10) => {
  const errorMap = {};
  entries.forEach(e => {
    if (e.type === 'error' && e.level === 'error' && e.ip) {
      errorMap[e.ip] = (errorMap[e.ip] || 0) + 1;
    }
  });
  return Object.entries(errorMap)
    .filter(([, count]) => count >= threshold)
    .map(([ip, count]) => ({ ip, count, type: 'Repeated Errors' }));
};

// error level breakdown for error logs
const getErrorBreakdown = (entries) => {
  const levels = {};
  entries.forEach(e => {
    if (e.type === 'error') {
      levels[e.level] = (levels[e.level] || 0) + 1;
    }
  });
  return levels;
};

// summary stats
const getSummary = (entries) => {
  const withIP = entries.filter(e => e.ip);
  return {
    totalRequests: entries.length,
    uniqueIPs: new Set(withIP.map(e => e.ip)).size,
    totalErrors: entries.filter(e => e.status >= 400 || e.level === 'error').length,
    logType: entries[0]?.type === 'error' ? 'Apache Error Log' : 'Apache Access Log',
    errorBreakdown: getErrorBreakdown(entries),
    top5IPs: Object.entries(
      withIP.reduce((acc, e) => { acc[e.ip] = (acc[e.ip] || 0) + 1; return acc; }, {})
    ).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([ip, count]) => ({ ip, count }))
  };
};

module.exports = { parseLine, detectBruteForce, detectHighVolume, detectScanner, detectRepeatedErrors, getSummary };
