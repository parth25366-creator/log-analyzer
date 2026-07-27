// Log Parser — detects suspicious patterns in server logs

// parse a single log line into structured object
const parseLine = (line) => {
  // Apache/Nginx combined log format:
  // IP - - [date] "METHOD /path HTTP/1.1" status bytes
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

module.exports = { parseLine };
