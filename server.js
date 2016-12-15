#!/usr/bin/env node
/* -*- Mode:js */
/* vim: set expandtab ts=4 sw=4: */
/*
 * You may redistribute this program and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
'use strict';
const Net = require('net');
const Udp = require('dgram');
const Crypto = require('crypto');
const Dijkstra = require('node-dijkstra');
const Bencode = require('bencode');
const Cjdnsplice = require('cjdnsplice');
const Walker = require('./walker');
const Cjdnskeys = require('cjdnskeys');
const Cjdnsniff = require('cjdnsniff');
const Cjdnsadmin = require('cjdnsadmin');
const Cjdnsann = require('../cjdnsann/index.js');
let Config = require('./config');

const FLUSH_STATE_CYCLE = 30000;
const RECONNECT_CHECK_CYCLE = 10000;
const RECONNECT_CYCLE = 250000;

const now = () => new Date().getTime();

const sendErr = (client, errorType, msg) => {
    try { client.end(JSON.stringify({'error': errorType, 'msg': msg}) + '\n'); } catch (e) { }
    return;
};

const buildGraph = (ctx) => {
    if (ctx.mut.dijkstra) { return; }
    const dijkstra = ctx.mut.dijkstra = new Dijkstra();
    for (const nk in ctx.nodes) {
        const links = ctx.nodes[nk].links;
        const l = {};
        for (const dk in links) {
            const dst = ctx.nodes[dk];
            if (!dst || !dst.links[nk]) { continue; }
            l[dk] = 1;
        }
        ctx.mut.dijkstra.addNode(nk, l);
    }
};

const getRoute = (ctx, src, dst) => {
    if (!src || !dst) { return null; }
    buildGraph(ctx);
    const path = ctx.mut.dijkstra.path(src.key, dst.key);
    if (!path) { return null; }
    let last;
    const labelPath = [];
    path.forEach((nn) => {
        const node = ctx.nodes[nn];
        const hop = {
            key: node.key,
            labelN: undefined,
            labelP: undefined,
            encodingScheme: node.encodingScheme
        };
        if (last) {
            labelPath[labelPath.length-1].labelN = last.links[nn].label;
            hop.labelP = node.links[last.key].label;
        }
        labelPath.push(hop);
        last = node;
    });
    const label = Cjdnsplice.buildLabel(labelPath);
    return { hops: labelPath, label: label.label, path: label.path };
};

const dropClient = (ctx, c) => {
    if (ctx.clients.indexOf(c) >= 0) {
        ctx.clients.splice(ctx.clients.indexOf(c), 1);
    }
    try { c.end() } catch (e) { }
};

const sendTo = (ctx, c, str) => {
    try {
        c.write(str);
    } catch (e) {
        dropClient(ctx, c);
    }
};

const bcast = (ctx, msg) => {
    const str = JSON.stringify(msg) + '\n';
    console.log('<' + JSON.stringify(msg));
    ctx.clients.forEach((c) => sendTo(ctx, c, str));
};

const sendState = (ctx, client) => {
    const out = [];
    for (const key in ctx.nodes) {
        const node = ctx.nodes[key];
        out.push(JSON.stringify(['node', node.version, key, node.encodingScheme, node.mut.time]));
        for (const peerKey in node.links) {
            const link = node.links[peerKey];
            out.push(JSON.stringify(['link', link.src, link.label, link.dst, link.mut.time]));
        }
    }
    out.push('');
    sendTo(ctx, client, out.join('\n'));
};

const nodesEqual = (a,b) => {
    return a.version === b.version &&
        a.key === b.key &&
        JSON.stringify(a.encodingScheme) === JSON.stringify(b.encodingScheme);
};

const handleMessage = (ctx, client, msgStr) => {
    let msg;
    if (typeof(msgStr) === 'string') {
        try { msg = JSON.parse(msgStr); } catch (e) {}
    } else {
        msg = msgStr;
    }
    if (!msg || typeof(msg) !== 'object' || !Array.isArray(msg) || msg.length < 2) {
        sendErr(client, 'malformed message', msgStr);
        return;
    }
    if (msg[0] === 'node') {
        const node = Object.freeze({
            version: msg[1],
            key: msg[2],
            encodingScheme: msg[3],
            links: {},
            mut: {
                time: msg[4]
            }
        });
        if (typeof(node.mut.time) !== 'number' || msg[5]) {
            sendErr(client, 'malformed node message');
            return;
        }
        const oldNode = ctx.nodes[node.key];
        //console.log('ctx.nodes[' + node.key + '] = ' + JSON.stringify(oldNode));
        if (oldNode) {
            if (oldNode.mut.time >= node.mut.time) { return; }
            oldNode.mut.time = node.mut.time;
            if (nodesEqual(oldNode, node)) { return; }
            //console.log(JSON.stringify(oldNode) + ' !== ' + JSON.stringify(node));
        } else {
            //console.log('new node ' + JSON.stringify(node));
        }
        ctx.nodes[node.key] = node;
        ctx.ipnodes[Cjdnskeys.publicToIp6(node.key)] = node;
        ctx.mut.dijkstra = undefined;
        bcast(ctx, msg);

    } else if (msg[0] === 'unlink') {
        const ulink = Object.freeze({
            src: msg[1],
            dst: msg[3],
            label: msg[2],
            mut: {
                time: msg[4]
            }
        });
        const srcNode = ctx.nodes[ulink.src];
        if (!srcNode) { return; }
        const oldLink = srcNode.links[ulink.dst];
        if (!oldLink || oldLink.mut.time >= ulink.mut.time) { return; }
        delete srcNode.links[ulink.dst];
        ctx.mut.dijkstra = undefined;
        bcast(ctx, msg);

    } else if (msg[0] === 'link') {
        const link = Object.freeze({
            src: msg[1],
            dst: msg[3],
            label: msg[2],
            mut: {
                time: msg[4]
            }
        });
        if (typeof(link.mut.time) !== 'number' || msg[5]) {
            sendErr(client, 'malformed link message');
            return;
        }
        const srcNode = ctx.nodes[link.src];
        if (!srcNode) { return; }
        try {
            if (!Cjdnsplice.isOneHop(link.label, srcNode.encodingScheme)) {
                console.log("multi-hop peer " + link.label);
                return;
            }
        } catch (e) { return; }
        const oldLink = srcNode.links[link.dst];
        if (oldLink) {
            if (oldLink.mut.time >= link.mut.time) { return; }
            oldLink.mut.time = link.mut.time;
            if (JSON.stringify(oldLink) === JSON.stringify(link)) { return; }
            console.log("link change " + link.src + " " + link.dst + ' ' + oldLink.label + ' ' + link.label);
        } else {
            console.log("new link " + link.src + " " + link.dst);
        }
        for (const ol in srcNode.links) {
            if (srcNode.links[ol].label !== link.label) { continue; }
            if (srcNode.links[ol].mut.time >= link.mut.time) { return; }
            delete srcNode.links[ol];
        }
        srcNode.links[link.dst] = link;
        ctx.mut.dijkstra = undefined;
        bcast(ctx, msg);

    } else {
        sendErr(client, 'unknown request');
    }
};

const onData = (ctx, data, dat, c) => {
    data.d += dat.toString('utf8');
    if (data.d.indexOf('\n') !== -1) {
        let lines = data.d.split('\n');
        data.d = lines.pop();
        lines.forEach((msg) => ( handleMessage(ctx, c, msg) ));
    }
};

const nodeAnnouncementHash = (node) => {
    let carry = new Buffer(64).fill(0);
    for (let i = node.mut.announcements.length - 1; i >= 0; i--) {
        const hash = Crypto.createHash('sha512').update(carry);
        carry = hash.update(node.mut.announcements[i].binary).digest();
    }
    return carry;
};

const replyAnnounce = (ctx, msg, node, cjdnslink, replyError) => {
    const hash = nodeAnnouncementHash(node);
    const responseBenc = {
        txid: msg.contentBenc.txid,
        p: 18,
        stateHash: hash,
        recvTime: +new Date()
    };
    msg.contentBenc = responseBenc;
    console.log("reply: " + hash.toString('hex'));
    cjdnslink.send(msg);
};

const AGREED_TIMEOUT_MS = (1000 * 60 * 60 * 20);
const MAX_CLOCKSKEW_MS = (1000 * 10);

const addAnnouncement = (node, ann) => {
    const time = Number('0x' + ann.timestamp);
    const sinceTime = time - AGREED_TIMEOUT_MS;
    const newAnnounce = [];
    const peersAnnounced = {};
    node.mut.announcements.unshift(ann);
    node.mut.announcements.forEach((a) => {
        if (Number('0x' + a.timestamp) < sinceTime) { return; }
        let safe = false;
        for (let i = 0; i < a.peers.length; i++) {
            if (peersAnnounced[a.peers[i].ipv6]) { continue; }
            safe = true;
            peersAnnounced[a.peers[i].ipv6] = true;
        }
        if (safe) { newAnnounce.push(a); }
    });
    node.mut.announcements.splice(0, node.mut.announcements.length);
    Array.prototype.push.apply(node.mut.announcements, newAnnounce);
};

const timeHex = (time) => {
    const hex = (+time).toString(16);
    return new Array(16 - hex.length).fill(0).join('') + hex;
};

const handleAnnounce = (ctx, msg, cjdnslink) => {
    //console.log(msg.contentBenc);
    //console.log(msg.contentBenc.ann.toString('hex'));
    let ann;
    let replyError;
    console.log("ann:" + Crypto.createHash('sha512').update(msg.contentBenc.ann).digest('hex'));
    try {
        ann = Cjdnsann.parse(msg.contentBenc.ann);
    } catch (e) {
        console.log("bad announcement [" + e.message + "]");
        replyError = "failed_parse_or_validate";
    }
    console.log(ann);
    console.log(+new Date());

    let node;
    if (ann) { node = ctx.nodes[ann.nodePubKey]; }

    if (ann && node && node.mut.timestamp > ann.timestamp) {
        console.log("old timestamp");
        replyError = "old_message";
        ann = undefined;
    }

    if (ann && Math.abs(new Date() - Number('0x' + ann.timestamp)) > MAX_CLOCKSKEW_MS) {
        console.log("unacceptably large clock skew " +
            (new Date() - Number('0x' + ann.timestamp)));
        replyError = "excessive_clock_skew";
        ann = undefined;
    } else {
        console.log("clock skew " + (new Date() - Number('0x' + ann.timestamp)));
    }

    let scheme;
    if (ann && ann.encodingScheme) {
        scheme = ann.encodingScheme.scheme;
    } else if (node) {
        scheme = node.encodingScheme;
    } else if (ann) {
        console.log("no encoding scheme");
        replyError = "no_encodingScheme";
        ann = undefined;
    }

    if (!ann) {
        node = node || { mut: { announcements: [ ] } };
        replyAnnounce(ctx, msg, node, cjdnslink, replyError);
        return;
    }

    const nodex = Object.freeze({
        version: msg.contentBenc.p,
        key: ann.nodePubKey,
        encodingScheme: scheme,
        links: {},
        mut: {
            timestamp: ann.timestamp,
            announcements: [ ann ]
        }
    });
    if (node) {
        if (node.mut.timestamp > ann.timestamp) {
            console.log("old announcement, drop");
            replyAnnounce(ctx, msg, node, cjdnslink);
            return;
        } else if (node.version !== nodex.version) {
            console.log("version change, replacing node");
            node = ctx.nodes[ann.nodePubKey] = nodex;
        } else if (JSON.stringify(node.encodingScheme) !== JSON.stringify(nodex.encodingScheme)) {
            console.log("encodingScheme change, replacing node");
            node = ctx.nodes[ann.nodePubKey] = nodex;
        } else if (ann.isReset) {
            console.log("reset message");
            node = ctx.nodes[ann.nodePubKey] = nodex;
        } else {
            addAnnouncement(node, ann);
        }
    } else {
        node = ctx.nodes[ann.nodePubKey] = nodex;
    }
    replyAnnounce(ctx, msg, node, cjdnslink);
    //ann.peers.forEach()
};

const service = (ctx) => {
    Cjdnsadmin.connectWithAdminInfo((cjdns) => {
        Cjdnsniff.sniffTraffic(cjdns, 'CJDHT', (err, ev) => {
            console.log("Connected to cjdns engine");
            if (err) { throw err; }
            ev.on('error', (e) => {
                console.error('sniffTraffic error');
                console.error(e.stack);
            });
            ev.on('message', (msg) => {
                console.log(msg);
                if (!ctx.thisNode) {
                    if (!msg.routeHeader.isIncoming) {
                        try {
                            const scheme = Cjdnsencode.parse(msg.contentBenc.es);
                            const thisNode = ctx.thisNode = Object.freeze({
                                version: msg.contentBenc.p,
                                key: msg.routeHeader.publicKey,
                                encodingScheme: scheme,
                                links: {},
                                mut: {
                                    timestamp: ann.timestamp,
                                    announcements: [ ]
                                }
                            });
                            ctx.nodes[msg.routeHeader.publicKey] = thisNode;
                            console.log("Got node information");
                        } catch (e) { }
                    }
                    return;
                }
                if (!msg.contentBenc.sq) { return; }
                console.log(msg.contentBenc.sq.toString('utf8'));
                if (msg.contentBenc.sq.toString('utf8') === 'gr') {
                    const srcIp = Cjdnskeys.ip6BytesToString(msg.contentBenc.src);
                    const tarIp = Cjdnskeys.ip6BytesToString(msg.contentBenc.tar);
                    const src = ctx.ipnodes[srcIp];
                    const tar = ctx.ipnodes[tarIp];
                    console.log("getRoute req " + srcIp + " " + tarIp);
                    const r = getRoute(ctx, src, tar);

                    if (r) {
                        console.log(">> " + r.label);
                        msg.contentBenc.n = Buffer.concat([
                            Cjdnskeys.keyStringToBytes(tar.key),
                            new Buffer(r.label.replace(/\./g, ''), 'hex')
                        ]);
                        msg.contentBenc.np = new Buffer([1, 17]);
                    } else {
                        console.log(">> not found ");
                    }
                    msg.contentBenc.recvTime = now();

                    delete msg.contentBenc.sq;
                    delete msg.contentBenc.src;
                    delete msg.contentBenc.tar;
                    ev.send(msg);
                } else if (msg.contentBenc.sq.toString('utf8') === 'ann') {
                    handleAnnounce(ctx, msg, ev);
                } else {
                    console.log(msg.contentBenc);
                }
            });
        });
    });
};

const backbone = (ctx) => {
    const bind = Config.backboneBind.slice(0);
    bind.push(() => {
        console.log('backbone server bound on ' + JSON.stringify(Config.backboneBind));
    });
    const server = Net.createServer((c) => {
        // 'connection' listener
        c.on('error', (e) => {
            console.log(e);
            try { c.end(); } catch (ee) { }
            if (ctx.clients.indexOf(c) >= 0) {
                ctx.clients.splice(ctx.clients.indexOf(c), 1);
            }
        });
        console.log('client connected');
        sendState(ctx, c);
        ctx.clients.push(c);
        c.on('end', () => {
            console.log('client disconnected');
            if (ctx.clients.indexOf(c) >= 0) {
                ctx.clients.splice(ctx.clients.indexOf(c), 1);
            }
        });
        //let data = {d:''};
        //c.on('data', (dat) => onData(ctx, data, dat, c));
    });
    server.listen.apply(server, bind);
};

const setupWalker = (ctx) => {
    const walkerLog = { write: (msg) => { console.log("walker: " + msg) } };
    const walk = () => {
        return; // TODO
        console.log("beginning network walk");
        Walker.walk(Config.walkerMagic, (lines) => {
            const nodeLine = lines.shift();
            if (!nodeLine) { return; }
            const key = nodeLine[2];
            handleMessage(ctx, walkerLog, nodeLine);
            const node = ctx.nodes[key];
            const oldLinks = node.links;
            const unlinks = [];
            const linksKeys = lines.map((l) => (l[3]));
            for (const k in oldLinks) {
                if (linksKeys.indexOf(k) === -1) {
                    unlinks.push(['unlink', node.key, oldLinks[k].label, k, node.mut.time]);
                }
            }
            unlinks.forEach((ul) => (handleMessage(ctx, walkerLog, ul)));
            lines.forEach((l) => (handleMessage(ctx, walkerLog, l)));
        }, () => {
            setTimeout(walk, Config.walkerCycle);
        });
    };
    walk();
};

const connectOut = (ctx) => {
    Config.connectTo.forEach((x) => {
        let sock;
        let tolm = now();
        const again = () => {
            const data = {d:''};
            const s = sock = Net.connect(x, () => { });
            s.on('connect', () => {
                console.log("connected " + JSON.stringify(x) + ' localPort ' + s.localPort);
                tolm = now();
            });
            s.on('data', (dat) => {
                if (s !== sock) { s.end(); return; }
                tolm = now();
                onData(ctx, data, dat, { write: (x) => console.log(x) });
            });
            s.on('end', () => {
                if (s !== sock) { return; }
                console.log("connection " + JSON.stringify(x) + " lost");
                sock = null;
            });
            s.on('error', () => {
                if (s !== sock) { s.end(); return; }
                sock.end();
                sock = null;
            });
        };
        again();
        setInterval(() => {
            if (sock && now() - tolm > RECONNECT_CYCLE) {
                console.log('no data in ' + RECONNECT_CYCLE + 'ms reconnecting');
                if (sock) { sock.end(); }
                sock = null;
                again();
            }
        }, RECONNECT_CHECK_CYCLE);
    });
};

const main = () => {
    const confIdx = process.argv.indexOf('--config');
    if (confIdx > -1) { Config = require(process.argv[confIdx+1]); }

    let ctx = Object.freeze({
        nodes: {},
        ipnodes: {},
        clients: [],
        mut: {
            dijkstra: undefined
        }
    });

    if (Config.backboneBind) { backbone(ctx); }
    if (Config.serviceBind) { service(ctx); }
    if (Config.walkerCycle) { setupWalker(ctx); }
    if (Config.connectTo.length) { connectOut(ctx); }
};
main();
