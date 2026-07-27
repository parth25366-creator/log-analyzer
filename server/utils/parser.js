// Log Parser — detects suspicious patterns in server logs

// parse a single log line into structured object
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

// detect brute force — IP with too many 401/403 responses
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

// detect suspicious IPs — too many requests overall
const detectHighVolume = (entries, threshold = 100) => {
  const ipMap = {};
  entries.forEach(e => {
    ipMap[e.ip] = (ipMap[e.ip] || 0) + 1;
  });
  return Object.entries(ipMap)
    .filter(([, count]) => count >= threshold)
    .map(([ip, count]) => ({ ip, count, type: 'High Volume' }));
};

module.exports = { parseLine, detectBruteForce, detectHighVolume };
