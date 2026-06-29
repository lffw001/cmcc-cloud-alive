#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const {
  parseZteCagDatagram,
  ZteCagTunnelType,
} = require('../lib/protocol');

function usage() {
  console.error('Usage: node scripts/extract-cag-tunnel-flow.js <cag.pcap> [--from SEC.USEC] [--to SEC.USEC] [--limit 80]');
  process.exit(2);
}

function parseArgs(argv) {
  const out = { _: [], from: null, to: null, limit: 80 };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--from') out.from = Number(argv[++i] || 0);
    else if (arg === '--to') out.to = Number(argv[++i] || 0);
    else if (arg === '--limit') out.limit = Number(argv[++i] || 0);
    else out._.push(arg);
  }
  return out;
}

function sha256Hex(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function packetTime(packet) {
  return `${packet.seconds}.${String(packet.micros).padStart(6, '0')}`;
}

function packetTimeNumber(packet) {
  return Number(packetTime(packet));
}

function inTimeWindow(packet, args) {
  const time = packetTimeNumber(packet);
  if (args.from !== null && time < args.from) return false;
  if (args.to !== null && time > args.to) return false;
  return true;
}

function parseClassicPcap(file) {
  const buffer = fs.readFileSync(file);
  if (buffer.length < 24) throw new Error('pcap file is too short');
  const magic = buffer.readUInt32LE(0);
  if (magic !== 0xa1b2c3d4 && magic !== 0xd4c3b2a1) {
    throw new Error('only classic little-endian pcap files are supported');
  }
  const linkType = buffer.readUInt32LE(20);

  let offset = 24;
  const packets = [];
  while (offset + 16 <= buffer.length) {
    const seconds = buffer.readUInt32LE(offset);
    const micros = buffer.readUInt32LE(offset + 4);
    const capturedLength = buffer.readUInt32LE(offset + 8);
    const packetOffset = offset + 16;
    offset = packetOffset + capturedLength;

    let ipOffset;
    if (linkType === 1) {
      if (capturedLength < 34) continue;
      if (buffer.readUInt16BE(packetOffset + 12) !== 0x0800) continue;
      ipOffset = packetOffset + 14;
    } else if (linkType === 276) {
      if (capturedLength < 40) continue;
      if (buffer.readUInt16BE(packetOffset) !== 0x0800) continue;
      ipOffset = packetOffset + 20;
    } else {
      throw new Error(`unsupported pcap link type: ${linkType}`);
    }

    const ipHeaderLength = (buffer[ipOffset] & 0x0f) * 4;
    if (buffer[ipOffset + 9] !== 17) continue;
    const l4Offset = ipOffset + ipHeaderLength;
    const udpLength = buffer.readUInt16BE(l4Offset + 4);
    packets.push({
      seconds,
      micros,
      sourceIp: [...buffer.subarray(ipOffset + 12, ipOffset + 16)].join('.'),
      destinationIp: [...buffer.subarray(ipOffset + 16, ipOffset + 20)].join('.'),
      sourcePort: buffer.readUInt16BE(l4Offset),
      destinationPort: buffer.readUInt16BE(l4Offset + 2),
      payload: buffer.subarray(l4Offset + 8, l4Offset + udpLength),
    });
  }
  return packets;
}

function firstRemoteHost(packets) {
  const counts = new Map();
  for (const packet of packets) {
    for (const ip of [packet.sourceIp, packet.destinationIp]) {
      if (ip.startsWith('127.')) continue;
      if (/^(10|172\.16|172\.17|172\.18|172\.19|172\.2\d|172\.3[01]|192\.168)\./.test(ip)) continue;
      counts.set(ip, (counts.get(ip) || 0) + 1);
    }
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || '';
}

function direction(packet, remoteHost) {
  if (remoteHost && packet.destinationIp === remoteHost) return 'client->cag';
  if (remoteHost && packet.sourceIp === remoteHost) return 'cag->client';
  return `${packet.sourceIp}:${packet.sourcePort}->${packet.destinationIp}:${packet.destinationPort}`;
}

function hex32(value) {
  return `0x${(Number(value) >>> 0).toString(16).padStart(8, '0')}`;
}

function tlsSummary(tunnel) {
  if (!tunnel.hasTlsRecord) return null;
  const record = tunnel.tlsRecord;
  if (record.length < 5) return { offset: tunnel.tlsRecordOffset };
  return {
    offset: tunnel.tlsRecordOffset,
    contentType: record[0],
    versionHex: record.subarray(1, 3).toString('hex'),
    recordLength: record.readUInt16BE(3),
    first12Hex: record.subarray(0, 12).toString('hex'),
  };
}

function eventSummary(packet, remoteHost, parsed) {
  const tunnel = parsed.tunnel;
  const header = tunnel.header;
  const base = {
    time: packetTime(packet),
    direction: direction(packet, remoteHost),
    source: `${packet.sourceIp}:${packet.sourcePort}`,
    destination: `${packet.destinationIp}:${packet.destinationPort}`,
    length: packet.payload.length,
    sha256: sha256Hex(packet.payload),
    word0Hex: hex32(header.word0),
    type: header.packetType,
    typeName: header.packetTypeName,
    flagByte: header.flagByte,
    sequence16: header.sequence16,
    word2Hex: hex32(header.word2),
    word3Hex: hex32(header.word3),
    word4Hex: hex32(header.word4),
    word5Hex: hex32(header.word5),
    payloadLength: tunnel.payloadLength,
    payloadLengthMatchesWord4: tunnel.payloadLengthMatchesWord4,
    tls: tlsSummary(tunnel),
  };
  if (header.shortTail?.length) base.shortTailHex = header.shortTail.toString('hex');
  if (header.packetType === ZteCagTunnelType.ACK) base.ackValue = header.word2;
  if (header.packetType === ZteCagTunnelType.CLIENT_CONTROL) {
    base.payloadFirst16Hex = tunnel.payload.subarray(0, 16).toString('hex');
  }
  return base;
}

function extract(file, args) {
  const packets = parseClassicPcap(file);
  const remoteHost = firstRemoteHost(packets);
  const events = [];

  for (const packet of packets) {
    if (!packet.payload.length || !inTimeWindow(packet, args)) continue;
    const parsed = parseZteCagDatagram(packet.payload);
    if (!parsed.tunnel) continue;
    events.push(eventSummary(packet, remoteHost, parsed));
  }

  const countsByType = {};
  const countsByDirectionAndType = {};
  const word0s = {};
  const dataRuns = new Map();
  const controlTailCounts = {};
  for (const event of events) {
    countsByType[event.typeName] = (countsByType[event.typeName] || 0) + 1;
    const dirType = `${event.direction}:${event.typeName}`;
    countsByDirectionAndType[dirType] = (countsByDirectionAndType[dirType] || 0) + 1;
    word0s[event.word0Hex] = (word0s[event.word0Hex] || 0) + 1;
    if (event.typeName === 'data') {
      const key = `${event.direction}:${event.sequence16}`;
      if (!dataRuns.has(key)) {
        dataRuns.set(key, {
          direction: event.direction,
          sequence16: event.sequence16,
          count: 0,
          payloadBytes: 0,
          tlsRecords: 0,
          firstTime: event.time,
          lastTime: event.time,
        });
      }
      const run = dataRuns.get(key);
      run.count++;
      run.payloadBytes += event.payloadLength;
      run.lastTime = event.time;
      if (event.tls) run.tlsRecords++;
    }
    if (event.typeName === 'control' && event.shortTailHex) {
      const key = `${event.direction}:${event.shortTailHex}`;
      controlTailCounts[key] = (controlTailCounts[key] || 0) + 1;
    }
  }

  return {
    file,
    packets: packets.length,
    remoteHost,
    timeWindow: args.from !== null || args.to !== null ? { from: args.from, to: args.to } : null,
    tunnelPackets: events.length,
    word0s,
    countsByType,
    countsByDirectionAndType,
    firstTlsRecords: events.filter((event) => event.tls).slice(0, args.limit),
    firstDataRuns: [...dataRuns.values()].slice(0, args.limit),
    controlTailCounts,
    ackValues: events
      .filter((event) => event.typeName === 'ack')
      .map((event) => ({
        time: event.time,
        direction: event.direction,
        sequence16: event.sequence16,
        ackValue: event.ackValue,
        word3Hex: event.word3Hex,
      }))
      .slice(0, args.limit),
    clientControls: events
      .filter((event) => event.typeName === 'client_control')
      .slice(0, args.limit),
    events: events.slice(0, args.limit),
  };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const file = args._[0];
  if (!file) usage();
  console.log(JSON.stringify(extract(file, args), null, 2));
}

main();
