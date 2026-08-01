// Log Parser — auto-detects and parses 15+ log formats

// ─── FORMAT DETECTION ───────────────────────────────────────────────────────

const detectFormat = (lines) => {
  const sample = lines.slice(0, 5).join('\n');

  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*\[.*\].*"(GET|POST|PUT|DELETE|HEAD)/.test(sample))
    return 'apache_access';
  if (/^\[.*\] \[(error|warn|notice|info)\]/.test(sample))
    return 'apache_error';
  if (/^\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2} \[(error|warn|notice|info)\]/.test(sample))
    return 'nginx_error';
  if (/nova-api|nova\.|neutron\.|keystone\.|glance\./.test(sample))
    return 'openstack';
  if (/^\d{6} \d{6} \d+ (INFO|WARN|ERROR|DEBUG) dfs\./.test(sample))
    return 'hdfs';
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} (INFO|WARN|ERROR|DEBUG).*hadoop/.test(sample))
    return 'hadoop';
  if (/^- \d+ \d{4}\.\d{2}\.\d{2} .* RAS /.test(sample))
    return 'bgl';
  if (/^\d{8}-\d{2}:\d{2}:\d{2}:\d{3}\|/.test(sample))
    return 'healthapp';
  if (/^\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}\s+\d+\s+\d+ [DVIWEF] /.test(sample))
    return 'android';
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}, (Info|Warning|Error)\s+CBS|CSI|DISM/.test(sample))
    return 'windows';
  if (/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}, (Info|Warning|Error)/.test(sample))
    return 'windows';
  if (/sshd\[\d+\]:.*Invalid user|Failed password|Accepted/.test(sample))
    return 'ssh_auth';
  if (/^\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}.*sshd/.test(sample))
    return 'ssh_auth';
  if (/^\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}.*kernel|com\.apple/.test(sample))
    return 'mac';
  if (/^\d+ node-\d+/.test(sample))
    return 'hpc';
  if (/^\{.*".*":.*\}/.test(sample))
    return 'json';

  return 'unknown';
};

// ─── PARSERS ────────────────────────────────────────────────────────────────

const parseApacheAccess = (line) => {
  const regex = /^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\S+)/;
  const match = line.match(regex);
  if (!match) return null;
  return { type: 'access', ip: match[1], date: match[2], method: match[3], path: match[4], status: parseInt(match[5]), bytes: match[6] };
};

const parseApacheError = (line) => {
  const regex = /^\[([^\]]+)\] \[(\w+)\] (.+)/;
  const match = line.match(regex);
  if (!match) return null;
  const ipMatch = match[3].match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  return { type: 'error', date: match[1], level: match[2], message: match[3], ip: ipMatch ? ipMatch[1] : null, status: match[2] === 'error' ? 500 : match[2] === 'warn' ? 400 : 200 };
};

const parseNginxError = (line) => {
  const regex = /^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] \d+#\d+: (.+)/;
  const match = line.match(regex);
  if (!match) return null;
  const ipMatch = match[3].match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  return { type: 'error', date: match[1], level: match[2], message: match[3], ip: ipMatch ? ipMatch[1] : null, status: match[2] === 'error' ? 500 : 200 };
};

const parseOpenStack = (line) => {
  const regex = /\S+\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+\d+\s+(\w+)\s+\S+\s+\[.*?\]\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"(\w+)\s+(\S+)\s+\S+"\s+status:\s+(\d+)/;
  const match = line.match(regex);
  if (!match) return null;
  return { type: 'access', date: match[1], level: match[2], ip: match[3], method: match[4], path: match[5], status: parseInt(match[6]) };
};

const parseHDFS = (line) => {
  const regex = /^(\d{6} \d{6}) (\d+) (\w+) (\S+): (.+)/;
  const match = line.match(regex);
  if (!match) return null;
  const ipMatch = match[5].match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  return { type: 'system', date: match[1], level: match[3], module: match[4], message: match[5], ip: ipMatch ? ipMatch[1] : null, status: match[3] === 'ERROR' ? 500 : match[3] === 'WARN' ? 400 : 200 };
};

const parseHadoop = (line) => {
  const regex = /^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) (\w+) \[([^\]]+)\] (\S+): (.+)/;
  const match = line.match(regex);
  if (!match) return null;
  const ipMatch = match[5].match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  return { type: 'system', date: match[1], level: match[2], thread: match[3], module: match[4], message: match[5], ip: ipMatch ? ipMatch[1] : null, status: match[2] === 'ERROR' ? 500 : match[2] === 'WARN' ? 400 : 200 };
};

const parseBGL = (line) => {
  const regex = /^- (\d+) (\d{4}\.\d{2}\.\d{2}) (\S+) (\S+) (\S+) (\w+) (\w+) (\w+) (.+)/;
  const match = line.match(regex);
  if (!match) return null;
  return { type: 'system', date: match[2], node: match[3], timestamp: match[4], level: match[8], message: match[9], ip: null, status: match[8] === 'FATAL' || match[8] === 'ERROR' ? 500 : match[8] === 'WARNING' ? 400 : 200 };
};

const parseHealthApp = (line) => {
  const regex = /^(\d{8}-\d{2}:\d{2}:\d{2}:\d{3})\|(\S+)\|(\S+)\|(.+)/;
  const match = line.match(regex);
  if (!match) return null;
  return { type: 'app', date: match[1], component: match[2], pid: match[3], message: match[4], ip: null, status: 200 };
};

const parseAndroid = (line) => {
  const regex = /^(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+\d+\s+\d+ ([DVIWEF]) ([^:]+): (.+)/;
  const match = line.match(regex);
  if (!match) return null;
  const levelMap = { D: 200, V: 200, I: 200, W: 400, E: 500, F: 500 };
  return { type: 'system', date: match[1], level: match[2], tag: match[3], message: match[4], ip: null, status: levelMap[match[2]] || 200 };
};

const parseWindows = (line) => {
  const regex = /^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}), (Info|Warning|Error)\s+(\w+)\s+(.+)/;
  const match = line.match(regex);
  if (!match) return null;
  return { type: 'system', date: match[1], level: match[2], component: match[3], message: match[4], ip: null, status: match[2] === 'Error' ? 500 : match[2] === 'Warning' ? 400 : 200 };
};

const parseSSHAuth = (line) => {
  const regex = /^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[[\d]+\]:\s+(.+)/;
  const match = line.match(regex);
  if (!match) return null;
  const msg = match[2];
  const ipMatch = msg.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  const failed = /failed password|invalid user|connection closed|disconnect|break-in/i.test(msg);
  const accepted = /accepted password|accepted publickey/i.test(msg);
  return { type: 'ssh', date: match[1], message: msg, ip: ipMatch ? ipMatch[1] : null, status: failed ? 401 : 200, failed, accepted };
};

const parseMac = (line) => {
  const regex = /^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^[]+)\[(\d+)\]: (.+)/;
  const match = line.match(regex);
  if (!match) return null;
  const ipMatch = match[5].match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  return { type: 'system', date: match[1], host: match[2], process: match[3].trim(), pid: match[4], message: match[5], ip: ipMatch ? ipMatch[1] : null, status: 200 };
};

const parseHPC = (line) => {
  const regex = /^(\d+) (node-\d+) (\S+) (\S+) (\d+) (\d+) (.+)/;
  const match = line.match(regex);
  if (!match) return null;
  return { type: 'system', id: match[1], node: match[2], category: match[3], event: match[4], date: match[5], message: match[7], ip: null, status: /unavailable|error|fail/i.test(match[4]) ? 500 : 200 };
};

const parseJSON = (line) => {
  try {
    const obj = JSON.parse(line);
    return { type: 'json', ip: obj.ip || obj.client_ip || obj.remote_addr || null, status: obj.status || obj.status_code || 200, method: obj.method || null, path: obj.path || obj.url || obj.uri || null, date: obj.time || obj.timestamp || null, message: obj.message || obj.msg || null, level: obj.level || obj.severity || null };
  } catch { return null; }
};

// ─── MAIN PARSE FUNCTION ────────────────────────────────────────────────────

const parseLine = (line, format) => {
  switch (format) {
    case 'apache_access': return parseApacheAccess(line);
    case 'apache_error':  return parseApacheError(line);
    case 'nginx_error':   return parseNginxError(line);
    case 'openstack':     return parseOpenStack(line);
    case 'hdfs':          return parseHDFS(line);
    case 'hadoop':        return parseHadoop(line);
    case 'bgl':           return parseBGL(line);
    case 'healthapp':     return parseHealthApp(line);
    case 'android':       return parseAndroid(line);
    case 'windows':       return parseWindows(line);
    case 'ssh_auth':      return parseSSHAuth(line);
    case 'mac':           return parseMac(line);
    case 'hpc':           return parseHPC(line);
    case 'json':          return parseJSON(line);
    default:
      return parseApacheAccess(line) || parseApacheError(line) ||
             parseSSHAuth(line) || parseHadoop(line) || parseJSON(line) || null;
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
  return Object.entries(failMap).filter(([, c]) => c >= threshold)
    .map(([ip, count]) => ({ ip, count, type: 'Brute Force' }));
};

const detectHighVolume = (entries, threshold = 100) => {
  const ipMap = {};
  entries.forEach(e => { if (e.ip) ipMap[e.ip] = (ipMap[e.ip] || 0) + 1; });
  return Object.entries(ipMap).filter(([, c]) => c >= threshold)
    .map(([ip, count]) => ({ ip, count, type: 'High Volume' }));
};

const detectScanner = (entries, threshold = 20) => {
  const scanMap = {};
  entries.forEach(e => { if (e.ip && e.status === 404) scanMap[e.ip] = (scanMap[e.ip] || 0) + 1; });
  return Object.entries(scanMap).filter(([, c]) => c >= threshold)
    .map(([ip, count]) => ({ ip, count, type: 'Scanner / Path Enumeration' }));
};

const detectRepeatedErrors = (entries, threshold = 10) => {
  const errorMap = {};
  entries.forEach(e => {
    if (e.ip && (e.level === 'error' || e.level === 'ERROR' || e.level === 'Error' || e.status >= 500)) {
      errorMap[e.ip] = (errorMap[e.ip] || 0) + 1;
    }
  });
  return Object.entries(errorMap).filter(([, c]) => c >= threshold)
    .map(([ip, count]) => ({ ip, count, type: 'Repeated Errors' }));
};

const detectSystemAnomalies = (entries, threshold = 50) => {
  const errCount = entries.filter(e => e.status >= 500 || e.level === 'ERROR' || e.level === 'FATAL' || e.level === 'Error').length;
  if (errCount >= threshold) {
    return [{ ip: 'System', count: errCount, type: 'High System Error Rate' }];
  }
  return [];
};

// ─── SUMMARY ────────────────────────────────────────────────────────────────

const formatLabels = {
  apache_access: 'Apache Access Log',
  apache_error:  'Apache Error Log',
  nginx_error:   'Nginx Error Log',
  openstack:     'OpenStack Log',
  hdfs:          'HDFS Log',
  hadoop:        'Hadoop Log',
  bgl:           'BGL Supercomputer Log',
  healthapp:     'HealthApp Log',
  android:       'Android Log',
  windows:       'Windows Event Log',
  ssh_auth:      'SSH Auth Log',
  mac:           'macOS System Log',
  hpc:           'HPC Log',
  json:          'JSON Log',
  unknown:       'Unknown Format'
};

const getSummary = (entries, format) => {
  const withIP = entries.filter(e => e.ip);
  return {
    totalRequests: entries.length,
    uniqueIPs: new Set(withIP.map(e => e.ip)).size,
    totalErrors: entries.filter(e => e.status >= 400 || e.level === 'ERROR' || e.level === 'Error' || e.failed).length,
    logType: formatLabels[format] || 'Unknown Format',
    top5IPs: Object.entries(
      withIP.reduce((acc, e) => { acc[e.ip] = (acc[e.ip] || 0) + 1; return acc; }, {})
    ).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([ip, count]) => ({ ip, count }))
  };
};

module.exports = {
  detectFormat, parseLine,
  detectBruteForce, detectHighVolume, detectScanner, detectRepeatedErrors, detectSystemAnomalies,
  getSummary
};
