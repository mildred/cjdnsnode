const WebSocket = require('ws');
const Msgpack = require('msgpack5');
const nThen = require('nthen');

const NOFUNC = ()=>{};

const DROP_AFTER_MS = 60000;
const PING_AFTER_MS = 20000;
const PING_CYCLE_MS = 5000;

const now = () => (+new Date());

const socketSendable = function (socket) {
    return socket && socket.readyState === 1;
};

const dropPeer = (ctx, peer) => {
    try { throw new Error(); } catch (e) { console.log(e.stack); }
    if (peer.socket.readyState !== 2 /* WebSocket.CLOSING */
        && peer.socket.readyState !== 3 /* WebSocket.CLOSED */)
    {
        try {
            peer.socket.close();
        } catch (e) {
            console.log("Failed to disconnect [" + peer.id + "], attempting to terminate");
            try {
                peer.socket.terminate();
            } catch (ee) {
                console.log("Failed to terminate [" + peer.id + "]  *shrug*");
            }
        }
    }
    const idx = ctx.peers.indexOf(peer);
    if (idx !== -1) {
        ctx.peers.splice(idx, 1);
    }
};

const sendPeerMsg = function (ctx, peer, msg) {
    if (!socketSendable(peer.socket)) { return; }
    try {
        peer.socket.send(ctx.msgpack.encode(msg));
    } catch (e) {
        console.log(e.stack);
        dropPeer(ctx, peer);
    }
};

const handleMessage = (ctx, peer, message) => {
    const msg = ctx.msgpack.decode(message);
    if (typeof(msg[0]) !== 'number' || typeof(msg[1]) !== 'string') {
        throw new Error();
    }
    peer.mut.timeOfLastMessage = now();
    switch (msg[1]) {
        case 'OLLEH':
        case 'HELLO': {
            if (('HELLO' === msg[1]) !== peer.outgoing) {
                console.log("bad hello message");
                dropPeer(ctx, peer);
                return;
            }
            console.log("Connected to snode with version [" + ctx.version + "]");
            return;
        }
        case 'GET_DATA': {
            const hash = msg[2].toString('hex');
            const ann = ctx.annByHash[hash] || null;
            console.log('>GET_DATA');
            sendPeerMsg(ctx, peer, [msg[0], 'DATA', ann]);
            return;
        }
        case 'PING': {
            console.log('>PING');
            sendPeerMsg(ctx, peer, [msg[0], 'ACK']);
            return;
        }
        case 'ACK': {
            console.log('>ACK');
            if (typeof(ctx.pings[peer.id]) === 'undefined') {
                console.log("ping ack without related ping");
                return;
            }
            const ping = ctx.pings[peer.id];
            if (String(ping.seq) !== String(msg[0])) {
                console.log("ping ack for seq [" + msg[0] + "] and ping is [" + ping.seq + "]");
                return;
            }
            delete ctx.pings[peer.id];
            return;
        }
        case 'INV': {
            if (!peer.outgoing) { return; }
            console.log('INV');
            const hexList = msg[3].map((x) => (x.toString('hex')));
            const needHex = hexList.filter((x) => (!(x in ctx.annByHash)));
            console.log("need: " + needHex.join('\n'));
            needHex.forEach((x) => {
                sendPeerMsg(ctx, peer, [ctx.mut.seq++, 'GET_DATA', new Buffer(x, 'hex')]);
            });
            return;
        }
        case 'DATA': {
            if (!peer.outgoing) { return; }
            ctx.mut.onAnnounce(peer, msg[2]);
        }
    }
};

const mkPeer = (ctx, socket, isOutgoing) => {
    const peer = {
        id: ctx.mut.peerIdSeq++,
        socket: socket,
        outgoing: isOutgoing,
        mut: {
            timeOfLastMessage: now()
        }
    };
    socket.peer = peer;
    return peer;
};

const incoming = (ctx, socket) => {
    if (socket.upgradeReq.url !== '/cjdnsnode_websocket') {
        socket.close();
        return;
    }
    const peer = mkPeer(ctx, socket, false);
    console.log("Incoming connection " + peer.addr);
    sendPeerMsg(ctx, peer, [0, 'HELLO', ctx.version]);
    ctx.peers.push(peer);
    const hashes = Object.keys(ctx.annByHash).map((x) => (new Buffer(x, 'hex')));
    sendPeerMsg(ctx, peer, [0, 'INV', 0, hashes]);
    socket.on('message', function(message) {
        try {
            handleMessage(ctx, peer, message);
        } catch (e) {
            console.log(e.stack);
            dropPeer(ctx, peer);
        }
    });
    socket.on('close', function (evt) {
        dropPeer(ctx, peer);
    });
};

const connectTo = (ctx, url) => {
    const socket = new WebSocket(url, {
        perMessageDeflate: false
    });
    socket.on('error', (e) => {
        console.log(e);
        setTimeout(() => { connectTo(ctx, url); }, 10000);
    });
    nThen((waitFor) => {
        socket.on('open', waitFor());
    }).nThen((waitFor) => {
        console.log('Connected to ' + url);
        const peer = mkPeer(ctx, socket, true);
        ctx.peers.push(peer);
        socket.on('message', function(message) {
            try {
                handleMessage(ctx, peer, message);
            } catch (e) {
                console.log(e.stack);
                dropPeer(ctx, peer);
            }
        });
        socket.on('close', function (evt) {
            dropPeer(ctx, peer);
            setTimeout(() => { connectTo(ctx, url); }, 1000);
        });
        sendPeerMsg(ctx, peer, [0, 'OLLEH', ctx.version]);
    });
};

const addAnn = (ctx, hash, binary) => {
    ctx.annByHash[hash] = binary;
    ctx.peers.forEach((p) => {
        if (!p.outgoing) { return; }
        sendPeerMsg(ctx, p, [0, 'INV', 0, [ new Buffer(hash, 'hex') ] ]);
    });
};

const pingCycle = (ctx) => {
    ctx.peers.forEach((p) => {
        const lag = now() - p.mut.timeOfLastMessage;
        if (lag > DROP_AFTER_MS) {
            dropPeer(ctx, p);
        } else if (lag > PING_AFTER_MS && typeof(ctx.pings[p.id]) === 'undefined') {
            const seq = ctx.mut.seq++;
            ctx.pings[p.id] = { seq: seq, time: now() };
            sendPeerMsg(ctx, p, [seq, 'PING']);
            console.log('<PING ' + seq);
        }
    });
};

const runServer = (ctx, httpServer) => {
    const wsSrv = new WebSocket.Server({ server: httpServer });
    wsSrv.on('connection', (socket) => { incoming(ctx, socket); });
};

const create = module.exports.create = () => {
    const ctx = Object.freeze({
        peers: [],
        pings: {},
        annByHash: {},
        msgpack: Msgpack(),
        version: 1,
        mut: {
            seq: +new Date(),
            peerIdSeq: 0,
            pingCycle: undefined,
            onAnnounce: NOFUNC,
        }
    });
    ctx.mut.pingCycle = setInterval(() => { pingCycle(ctx); }, PING_CYCLE_MS);

    return {
        connectTo: (url) => { connectTo(ctx, url); },
        addAnn: (hash, binary) => { addAnn(ctx, hash, binary); },
        deleteAnn: (hash) => { delete ctx.annByHash[hash]; },
        runServer: (httpServer) => { runServer(ctx, httpServer); },
        onAnnounce: (handler) => { ctx.mut.onAnnounce = handler; }
    };
};
