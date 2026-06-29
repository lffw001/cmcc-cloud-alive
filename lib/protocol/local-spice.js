'use strict';

const {
  decodeDataMessage,
  decodeSpiceAuthResult,
  decodeSpiceLinkMess,
  decodeSpiceLinkReply,
  encodeDataMessage,
  SpiceMessage,
} = require('./spice');
const {
  ProtocolStage,
  applyProtocolEvent,
  createProtocolProgress,
  isProtocolKeepaliveSuccess,
} = require('./events');

const LOCAL_SPICE_EXT_INFO_SIZE = 164;
const LOCAL_SPICE_PRIMARY_ID_OFFSET = 0x6c;
const LOCAL_SPICE_PRIMARY_ID_SIZE = 0x20;
const LOCAL_SPICE_SECONDARY_ID_OFFSET = 0x8d;
const LOCAL_SPICE_SECONDARY_ID_SIZE = 0x10;
const LOCAL_SPICE_CLIENT_FRAME_HEADER_SIZE = 4;
const LOCAL_SPICE_CLIENT_FRAME_MARKER = 0x0a;
const LINUX_DISPLAY_INIT_PAYLOAD = Buffer.from('000100004001000000000100fc5f0000000000', 'hex');

function readAsciiField(buffer, offset, size) {
  const raw = buffer.subarray(offset, offset + size);
  const nul = raw.indexOf(0);
  return raw.subarray(0, nul === -1 ? raw.length : nul).toString('ascii');
}

function writeAsciiField(buffer, offset, size, value) {
  const text = Buffer.from(String(value || ''), 'ascii');
  if (text.length > size) throw new Error(`ASCII field is too long for ${size}-byte field`);
  text.copy(buffer, offset);
}

function encodeLocalSpiceExtInfo(opts = {}) {
  const channelPrefix = opts.channelPrefix ?? (opts.channelClass === 3 ? 2 : 1);
  const channelClass = opts.channelClass ?? (channelPrefix === 2 ? 3 : 1);
  const out = Buffer.alloc(LOCAL_SPICE_EXT_INFO_SIZE);
  out.writeUInt16LE(opts.field00 ?? 0x001a, 0x00);
  out.writeUInt16LE(opts.field02 ?? 0x009c, 0x02);
  out.writeUInt16LE(opts.localPortHint ?? 0x2710, 0x04);
  out.writeUInt16LE(channelClass, 0x06);
  out.writeUInt16LE(opts.field08 ?? 0x0280, 0x08);
  out.writeUInt16LE(opts.field0a ?? 0x0a0a, 0x0a);
  writeAsciiField(out, LOCAL_SPICE_PRIMARY_ID_OFFSET, LOCAL_SPICE_PRIMARY_ID_SIZE, opts.primaryId);
  writeAsciiField(out, LOCAL_SPICE_SECONDARY_ID_OFFSET, LOCAL_SPICE_SECONDARY_ID_SIZE, opts.secondaryId);
  out.writeUInt16BE(opts.field9eBe ?? channelPrefix, 0x9e);
  out.writeUInt16BE(opts.fielda0Be ?? (0x0a00 | channelPrefix), 0xa0);
  out.writeUInt16LE(opts.fielda2Le ?? (channelPrefix === 2 ? 0x02dd : 0x02d9), 0xa2);
  return out;
}

function decodeLocalSpiceExtInfo(input) {
  const buffer = Buffer.from(input);
  if (buffer.length < LOCAL_SPICE_EXT_INFO_SIZE) {
    throw new Error(`local SPICE ExtInfo requires ${LOCAL_SPICE_EXT_INFO_SIZE} bytes`);
  }
  return {
    raw: buffer.subarray(0, LOCAL_SPICE_EXT_INFO_SIZE),
    field00: buffer.readUInt16LE(0x00),
    field02: buffer.readUInt16LE(0x02),
    localPortHint: buffer.readUInt16LE(0x04),
    channelClass: buffer.readUInt16LE(0x06),
    field08: buffer.readUInt16LE(0x08),
    field0a: buffer.readUInt16LE(0x0a),
    primaryId: readAsciiField(buffer, LOCAL_SPICE_PRIMARY_ID_OFFSET, LOCAL_SPICE_PRIMARY_ID_SIZE),
    secondaryId: readAsciiField(buffer, LOCAL_SPICE_SECONDARY_ID_OFFSET, LOCAL_SPICE_SECONDARY_ID_SIZE),
    field9eBe: buffer.readUInt16BE(0x9e),
    fielda0Be: buffer.readUInt16BE(0xa0),
    fielda2Le: buffer.readUInt16LE(0xa2),
  };
}

function decodeLocalSpiceClientHandshake(input) {
  const buffer = Buffer.from(input);
  const extInfo = decodeLocalSpiceExtInfo(buffer);
  const redqOffset = buffer.indexOf(Buffer.from('REDQ', 'ascii'), LOCAL_SPICE_EXT_INFO_SIZE);
  if (redqOffset !== LOCAL_SPICE_EXT_INFO_SIZE) {
    throw new Error(`local SPICE client REDQ expected at ${LOCAL_SPICE_EXT_INFO_SIZE}, got ${redqOffset}`);
  }
  const link = decodeSpiceLinkMess(buffer.subarray(redqOffset));
  return {
    extInfo,
    redqOffset,
    link,
    rest: link.rest,
  };
}

function encodeLocalSpiceClientHandshake(opts = {}) {
  return Buffer.concat([
    encodeLocalSpiceExtInfo(opts.extInfo || opts),
    Buffer.from(opts.link),
  ]);
}

function decodeLocalSpiceServerHandshake(input) {
  const buffer = Buffer.from(input);
  if (buffer.length < 2) throw new Error('local SPICE server handshake is too short');
  const channelPrefix = buffer.readUInt8(0);
  const redqOffset = buffer.indexOf(Buffer.from('REDQ', 'ascii'));
  if (redqOffset !== 1) {
    throw new Error(`local SPICE server REDQ expected at 1, got ${redqOffset}`);
  }
  const reply = decodeSpiceLinkReply(buffer.subarray(redqOffset));
  return {
    channelPrefix,
    redqOffset,
    reply,
    rest: reply.rest,
  };
}

function encodeLocalSpiceAuthResult(code = 0) {
  const out = Buffer.alloc(4);
  out.writeUInt32LE(Number(code) >>> 0, 0);
  return out;
}

function encodeLocalSpiceServerHandshake(opts = {}) {
  const channelPrefix = opts.channelPrefix ?? 1;
  return Buffer.concat([
    Buffer.from([channelPrefix]),
    Buffer.from(opts.linkReply),
    opts.authResult === undefined ? Buffer.alloc(0) : encodeLocalSpiceAuthResult(opts.authResult),
    Buffer.from(opts.data || []),
  ]);
}

function decodeLocalSpiceServerDataMessages(input, opts = {}) {
  const buffer = Buffer.from(input);
  const includeAuthResult = opts.includeAuthResult !== false;
  const maxMessages = opts.maxMessages ?? 128;
  const messages = [];
  let cursor = buffer;
  let offset = 0;
  let authResult = null;

  if (includeAuthResult) {
    authResult = decodeSpiceAuthResult(cursor);
    cursor = authResult.rest;
    offset += 4;
  }

  while (cursor.length >= 18 && messages.length < maxMessages) {
    let msg;
    try {
      msg = decodeDataMessage(cursor);
    } catch (err) {
      return {
        authResult,
        messages,
        rest: cursor,
        error: err,
        errorOffset: offset,
      };
    }
    const messageLength = 18 + msg.header.size;
    let paddingLength = 0;
    if (msg.rest.length > 0 && msg.rest[0] === 0x00) {
      paddingLength = 1;
    }
    messages.push({
      offset,
      header: msg.header,
      payload: msg.payload,
      paddingLength,
    });
    cursor = msg.rest.subarray(paddingLength);
    offset += messageLength + paddingLength;
  }

  return {
    authResult,
    messages,
    rest: cursor,
    error: null,
    errorOffset: null,
  };
}

function decodeLocalSpiceClientFrames(input, opts = {}) {
  const buffer = Buffer.from(input);
  const maxFrames = opts.maxFrames ?? 128;
  const frames = [];
  let offset = 0;

  while (offset + LOCAL_SPICE_CLIENT_FRAME_HEADER_SIZE <= buffer.length && frames.length < maxFrames) {
    const marker = buffer.readUInt8(offset);
    if (marker !== LOCAL_SPICE_CLIENT_FRAME_MARKER) {
      return {
        frames,
        rest: buffer.subarray(offset),
        error: new Error(`local SPICE client frame marker must be 0x0a, got 0x${marker.toString(16)}`),
        errorOffset: offset,
      };
    }
    const channelPrefix = buffer.readUInt8(offset + 1);
    const payloadLength = buffer.readUInt16LE(offset + 2);
    const payloadOffset = offset + LOCAL_SPICE_CLIENT_FRAME_HEADER_SIZE;
    const nextOffset = payloadOffset + payloadLength;
    if (nextOffset > buffer.length) {
      return {
        frames,
        rest: buffer.subarray(offset),
        error: new Error(`local SPICE client frame incomplete: need ${nextOffset}, got ${buffer.length}`),
        errorOffset: offset,
      };
    }
    frames.push({
      offset,
      channelPrefix,
      payloadLength,
      payload: buffer.subarray(payloadOffset, nextOffset),
    });
    offset = nextOffset;
  }

  return {
    frames,
    rest: buffer.subarray(offset),
    error: null,
    errorOffset: null,
  };
}

function encodeLocalSpiceClientFrame(channelPrefix, payload) {
  const body = Buffer.from(payload || []);
  if (!Number.isInteger(channelPrefix) || channelPrefix < 0 || channelPrefix > 0xff) {
    throw new Error('channelPrefix must be uint8');
  }
  if (body.length > 0xffff) throw new Error('local SPICE client frame payload is too large');
  const head = Buffer.alloc(LOCAL_SPICE_CLIENT_FRAME_HEADER_SIZE);
  head.writeUInt8(LOCAL_SPICE_CLIENT_FRAME_MARKER, 0);
  head.writeUInt8(channelPrefix, 1);
  head.writeUInt16LE(body.length, 2);
  return Buffer.concat([head, body]);
}

function encodeLocalSpiceAuthFrame(ticketCiphertext, opts = {}) {
  const ticket = Buffer.from(ticketCiphertext || []);
  if (ticket.length !== 128) throw new Error('local SPICE ticket auth frame requires a 128-byte ciphertext');
  return encodeLocalSpiceClientFrame(opts.channelPrefix ?? 1, ticket);
}

function encodeLocalSpiceClientDataFrame(type, payload = Buffer.alloc(0), opts = {}) {
  const message = encodeDataMessage(type, payload, {
    serial: opts.serial ?? 1n,
    subList: opts.subList ?? 0,
  });
  return encodeLocalSpiceClientFrame(
    opts.channelPrefix ?? 1,
    Buffer.concat([message, Buffer.from(opts.trailer || [])]),
  );
}

function encodeLinuxDisplayInitPayload(opts = {}) {
  if (opts.raw) {
    const raw = Buffer.from(opts.raw);
    if (raw.length !== LINUX_DISPLAY_INIT_PAYLOAD.length) {
      throw new Error(`Linux display init payload must be ${LINUX_DISPLAY_INIT_PAYLOAD.length} bytes`);
    }
    return raw;
  }
  return Buffer.from(LINUX_DISPLAY_INIT_PAYLOAD);
}

function encodeLocalSpiceDisplayInitFrame(opts = {}) {
  return encodeLocalSpiceClientDataFrame(
    SpiceMessage.DISPLAY_INIT,
    encodeLinuxDisplayInitPayload(opts),
    {
      channelPrefix: opts.channelPrefix ?? 2,
      serial: opts.serial ?? 1n,
      trailer: opts.trailer ?? Buffer.from([0x03]),
    },
  );
}

function encodeLocalSpiceAckSyncFrame(generation, opts = {}) {
  const payload = Buffer.alloc(4);
  payload.writeUInt32LE(Number(generation) >>> 0, 0);
  return encodeLocalSpiceClientDataFrame(SpiceMessage.ACK_SYNC, payload, {
    channelPrefix: opts.channelPrefix ?? 2,
    serial: opts.serial ?? 1n,
    trailer: opts.trailer ?? Buffer.alloc(0),
  });
}

function encodeLocalSpiceAckFrame(opts = {}) {
  return encodeLocalSpiceClientDataFrame(SpiceMessage.ACK, Buffer.alloc(0), {
    channelPrefix: opts.channelPrefix ?? 2,
    serial: opts.serial ?? 1n,
    trailer: opts.trailer ?? Buffer.alloc(0),
  });
}

function encodeLocalSpicePongFrame(pingPayload = Buffer.alloc(0), opts = {}) {
  return encodeLocalSpiceClientDataFrame(SpiceMessage.PONG, Buffer.from(pingPayload || []), {
    channelPrefix: opts.channelPrefix ?? 2,
    serial: opts.serial ?? 1n,
    trailer: opts.trailer ?? Buffer.alloc(0),
  });
}

function decodeLocalSpiceClientDataMessages(input, opts = {}) {
  const decoded = decodeLocalSpiceClientFrames(input, opts);
  const messages = [];
  let authFrame = null;
  for (const frame of decoded.frames) {
    if (!authFrame && frame.payloadLength === 128) {
      authFrame = frame;
      continue;
    }
    let msg;
    try {
      msg = decodeDataMessage(frame.payload);
    } catch (err) {
      return {
        authFrame,
        messages,
        frames: decoded.frames,
        rest: decoded.rest,
        error: err,
        errorOffset: frame.offset,
      };
    }
    const messageLength = 18 + msg.header.size;
    const trailer = frame.payload.subarray(messageLength);
    messages.push({
      frameOffset: frame.offset,
      channelPrefix: frame.channelPrefix,
      header: msg.header,
      payload: msg.payload,
      trailer,
    });
  }
  return {
    authFrame,
    messages,
    frames: decoded.frames,
    rest: decoded.rest,
    error: decoded.error,
    errorOffset: decoded.errorOffset,
  };
}

function createLocalSpiceOfflineDisplayProof(opts = {}) {
  let progress = createProtocolProgress();
  const setAckPayload = Buffer.alloc(8);
  setAckPayload.writeUInt32LE(opts.generation ?? 1, 0);
  setAckPayload.writeUInt32LE(opts.ackWindow ?? 70, 4);
  const pingPayload = Buffer.from(opts.pingPayload || '0102030405060708', 'hex');

  const displayInitFrame = encodeLocalSpiceDisplayInitFrame({ serial: opts.displaySerial ?? 1n });
  const decodedClient = decodeLocalSpiceClientDataMessages(displayInitFrame, { maxFrames: 4 });
  if (decodedClient.messages.some((msg) => msg.header.type === SpiceMessage.DISPLAY_INIT)) {
    progress = applyProtocolEvent(progress, ProtocolStage.DISPLAY_INIT_SENT);
  }

  const serverData = Buffer.concat([
    encodeLocalSpiceAuthResult(0),
    encodeDataMessage(SpiceMessage.SET_ACK, setAckPayload, { serial: 1n }),
    encodeDataMessage(SpiceMessage.PING, pingPayload, { serial: 2n }),
    encodeDataMessage(SpiceMessage.SURFACE_CREATE, Buffer.alloc(20), { serial: 3n }),
    encodeDataMessage(SpiceMessage.MARK, Buffer.alloc(0), { serial: 4n }),
  ]);
  const decodedServer = decodeLocalSpiceServerDataMessages(serverData, { maxMessages: 8 });
  const responseFrames = [];
  for (const msg of decodedServer.messages) {
    if (msg.header.type === SpiceMessage.SET_ACK) {
      progress = applyProtocolEvent(progress, ProtocolStage.SET_ACK_RECEIVED);
      const generation = msg.payload.readUInt32LE(0);
      responseFrames.push(encodeLocalSpiceAckSyncFrame(generation, { serial: BigInt(responseFrames.length + 1) }));
      progress = applyProtocolEvent(progress, ProtocolStage.ACK_SYNC_SENT);
    } else if (msg.header.type === SpiceMessage.PING) {
      progress = applyProtocolEvent(progress, ProtocolStage.PING_RECEIVED);
      responseFrames.push(encodeLocalSpicePongFrame(msg.payload, { serial: BigInt(responseFrames.length + 1) }));
      progress = applyProtocolEvent(progress, ProtocolStage.PONG_SENT);
    } else if (msg.header.type === SpiceMessage.SURFACE_CREATE) {
      progress = applyProtocolEvent(progress, ProtocolStage.SURFACE_CREATE_RECEIVED);
    } else if (msg.header.type === SpiceMessage.DRAW_COPY) {
      progress = applyProtocolEvent(progress, ProtocolStage.DRAW_COPY_RECEIVED);
    } else if (msg.header.type === SpiceMessage.MARK) {
      progress = applyProtocolEvent(progress, ProtocolStage.MARK_RECEIVED);
    }
  }

  return {
    displayInitFrame,
    serverData,
    responseFrames,
    decodedClient,
    decodedServer,
    progress,
    success: isProtocolKeepaliveSuccess(progress),
  };
}

module.exports = {
  LOCAL_SPICE_EXT_INFO_SIZE,
  LOCAL_SPICE_PRIMARY_ID_OFFSET,
  LOCAL_SPICE_PRIMARY_ID_SIZE,
  LOCAL_SPICE_SECONDARY_ID_OFFSET,
  LOCAL_SPICE_SECONDARY_ID_SIZE,
  LOCAL_SPICE_CLIENT_FRAME_HEADER_SIZE,
  LOCAL_SPICE_CLIENT_FRAME_MARKER,
  LINUX_DISPLAY_INIT_PAYLOAD,
  encodeLocalSpiceExtInfo,
  decodeLocalSpiceExtInfo,
  encodeLocalSpiceClientHandshake,
  decodeLocalSpiceClientHandshake,
  encodeLocalSpiceServerHandshake,
  decodeLocalSpiceServerHandshake,
  encodeLocalSpiceAuthResult,
  decodeLocalSpiceServerDataMessages,
  encodeLocalSpiceClientFrame,
  encodeLocalSpiceAuthFrame,
  encodeLocalSpiceClientDataFrame,
  encodeLinuxDisplayInitPayload,
  encodeLocalSpiceDisplayInitFrame,
  encodeLocalSpiceAckSyncFrame,
  encodeLocalSpiceAckFrame,
  encodeLocalSpicePongFrame,
  decodeLocalSpiceClientFrames,
  decodeLocalSpiceClientDataMessages,
  createLocalSpiceOfflineDisplayProof,
};
