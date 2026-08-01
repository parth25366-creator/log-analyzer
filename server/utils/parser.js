// Log Parser — auto-detects format and parses accordingly

// ─── FORMAT DETECTION ───────────────────────────────────────────────────────

const detectFormat = (lines) => {
  const sample = lines.slice(0, 5).join('\n');

  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*\[.*\].*"(GET|POST|PUT|DELETE|HEAD)/.test(sample))
    return 'apache_access';

  if (/^\[.*\] \[(error|warn|notice|info)\]/.test(sample))
    return 'apache_error';

  if (/^\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2} \[(error|warn|notice|info)\]/.test(sample))
    return 'nginx_error';

  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} - - \[/.test(sample))
    return 'nginx_access';

  if (/^[A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}.*sshd.*/.test(sample))
    return 'ssh_auth';

  if (/^\{.*".*":.*\}/.test(sample))
    return 'json';

  return 'unknown';
};

// ─── PARSERS ────────────────────────────────────────────────────────────────

const parseApacheAccess = (line) => {
  const regex = /^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\S+)/;
  const match = line.match(regex);
  if (!match) return null;
  return {
    type: 'access', ip: match[1], date: match[2],
    method: match[3], path: match[4],
    status: parseInt(match[5]), bytes: match[6]
  };
};

const parseApacheError = (line) => {
  const regex = /^\[([^\]]+)\] \[(\w+)\] (.+)/;
  const match = line.match(regex);
  if (!match) return null;
  const ipMatch = match[3].match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  return {
    type: 'error', date: match[1], level: match[2],
    message: match[3], ip: ipMatch ? ipMatch[1] : null,
    status: match[2] === 'error' ? 500 : match[2] === 'warn' ? 400 : 200
  };
};

const parseNginxError = (line) => {
  const regex = /^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] \d+#\d+: (.+)/;
  const match = line.match(regex);
  if (!match) return null;
  const ipMatch = match[3].match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  return {
    type: 'error', date: match[1], level: match[2],
    message: match[3], ip: ipMatch ? ipMatch[1] : null,
    status: match[2] === 'error' ? 500 : 200
  };
};

const parseNginxAccess = (line) => parseApacheAccess(line);

const parseSSHAuth = (line) => {
  const regex = /^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[[\d]+\]:\s+(.+)/;
  const match = line.match(regex);
  if (!match) return null;
  const msg = match[2];
  const ipMatch = msg.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  const failed = /failed password|invalid user|connection closed|disconnect/i.test(msg);
  const accepted = /accepted password|accepted publickey/i.test(msg);
  return {
    type: 'ssh', date: match[1], message: msg,
    ip: ipMatch ? ipMatch[1] : null,
    status: failed ? 401 : accepted ? 200 : 200,
    failed, accepted
  };
};

const parseJSON = (line) => {
  try {
    const obj = JSON.parse(line);
    return {
      type: 'json',
      ip: obj.ip || obj.client_ip || obj.remote_addr || null,
      status: obj.status || obj.status_code || 200,
      method: obj.method || obj.http_method || null,
      path: obj.path || obj.url || obj.uri || null,
      date: obj.time || obj.timestamp || obj.date || null,
      message: obj.message || obj.msg || null,
      level: obj.level || obj.severity || null
    };
  } catch { return null; }
};

// ─── MAIN PARSE FUNCTION ────────────────────────────────────────────────────

const parseLine = (line, format) => {
  switch (format) {
    case 'apache_access': return parseApacheAccess(line);
    case 'apache_error':  return parseApacheError(line);
    case 'nginx_access':  return parseNginxAccess(line);
    case 'nginx_error':   return parseNginxError(line);
    case 'ssh_auth':      return parseSSHAuth(line);
    case 'json':          return parseJSON(line);
    default:
      return parseApacheAccess(line) || parseApacheError(line) ||
             parseNginxError(line) || parseSSHAuth(line) || parseJSON(line);
  }
};

// ─── DETECTIONS ─────────────────────────────────────────────────────────────

const detectBruteForce = (entries, threshold = 10) => {
  const failMap = {};
  entries.forEach(e => {
    if (e.ip && (e.status === 401 || e.status === 403 || e.failed)) {
      failMap[e.ip] = (failMap[e.ip] || 0) + 1;
    }
  });
  return Object.entries(failMap)
    .filter(([, c]) => c >= threshold)
    .map(([ip, count]) => ({ ip, count, type: 'Brute Force' }));
};

const detectHighVolume = (entries, threshold = 100) => {
  const ipMap = {};
  entries.forEach(e => { if (e.ip) ipMap[e.ip] = (ipMap[e.ip] || 0) + 1; });
  return Object.entries(ipMap)
    .filter(([, c]) => c >= threshold)
    .map(([ip, count]) => ({ ip, count, type: 'High Volume' }));
};

const detectScanner = (entries, threshold = 20) => {
  const scanMap = {};
  entries.forEach(e => {
    if (e.ip && e.status === 404) scanMap[e.ip] = (scanMap[e.ip] || 0) + 1;
  });
  return Object.entries(scanMap)
    .filter(([, c]) => c >= threshold)
    .map(([ip, count]) => ({ ip, count, type: 'Scanner / Path Enumeration' }));
};

const detectRepeatedErrors = (entries, threshold = 10) => {
  const errorMap = {};
  entries.forEach(e => {
    if (e.ip && (e.level === 'error' || e.status >= 500)) {
      errorMap[e.ip] = (errorMap[e.ip] || 0) + 1;
    }
  });
  return Object.entries(errorMap)
    .filter(([, c]) => c >= threshold)
    .map(([ip, count]) => ({ ip, count, type: 'Repeated Errors' }));
};

// ─── SUMMARY ────────────────────────────────────────────────────────────────

const formatLabels = {
  apache_access: 'Apache Access Log',
  apache_error:  'Apache Error Log',
  nginx_access:  'Nginx Access Log',
  nginx_error:   'Nginx Error Log',
  ssh_auth:      'SSH Auth Log',
  json:          'JSON Log',
  unknown:       'Unknown Format'
};

const getSummary = (entries, format) => {
  const withIP = entries.filter(e => e.ip);
  return {
    totalRequests: entries.length,
    uniqueIPs: new Set(withIP.map(e => e.ip)).size,
    totalErrors: entries.filter(e => e.status >= 400 || e.level === 'error' || e.failed).length,
    logType: formatLabels[format] || 'Unknown Format',
    top5IPs: Object.entries(
      withIP.reduce((acc, e) => { acc[e.ip] = (acc[e.ip] || 0) + 1; return acc; }, {})
    ).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([ip, count]) => ({ ip, count }))
  };
};

module.exports = {
  detectFormat, parseLine,
  detectBruteForce, detectHighVolume, detectScanner, detectRepeatedErrors,
  getSummary
};
