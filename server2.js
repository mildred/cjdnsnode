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
const nThen = require('nthen');
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

const dropClient = (ctx, c) => {
    if (ctx.clients.indexOf(c) >= 0) {
        ctx.clients.splice(ctx.clients.indexOf(c), 1);
    }
    try { c.end(); } catch (e) { }
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
const setupWalker = (ctx) => {
    const walkerLog = { write: (msg) => { console.log("walker: " + msg); } };
    const walk = () => {
        return; /* TODO
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
        }); */
    };
    walk();
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



const connectOut = (ctx) => {
    Config.connectTo.forEach((x) => {
        let sock;
        let tolm = now();
        const again = () => {
            const data = {d:''};
            const s = Net.connect(x, () => { });
            sock = s;
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


//-----









// DONE
// test dijkstra
// 10 minute expiration

// TODO
// statefullness
// fix encodingFormNum
// re-enable walking...
// bootstrapping on subnode




const mkLink = (annPeer, ann) => {
    return Object.freeze({
        label: annPeer.label,
        mtu: annPeer.mtu,
        drops: annPeer.drops,
        latency: annPeer.latency,
        penalty: annPeer.penalty,
        encodingFormNum: annPeer.encodingFormNum,
        flags: annPeer.flags,
        time: Number('0x' + ann.timestamp)
    });
};

const linkValue = (link) => {
    return 1;
};

const buildGraph = (ctx) => {
    if (ctx.mut.dijkstra) { return; }
    const dijkstra = ctx.mut.dijkstra = new Dijkstra();
    for (const nip in ctx.nodesByIp) {
        const links = ctx.nodesByIp[nip].inwardLinksByIp;
        const l = {};
        for (const pip in links) { l[pip] = linkValue(links[pip]); }
        ctx.mut.dijkstra.addNode(nip, l);
    }
};

const getRoute = (ctx, src, dst) => {
    if (!src || !dst) { return null; }
    buildGraph(ctx);
    // we ask for the path in reverse because we build the graph in reverse.
    // because nodes announce own their reachability instead of announcing reachability of others.
    const path = ctx.mut.dijkstra.path(dst.ipv6, src.ipv6);
    if (!path) { return; }
    path.reverse();
    let last;
    let lastLink;
    const hops = [];
    const labels = [];
    let formNum;

    path.forEach((nip) => {
        const node = ctx.nodesByIp[nip];
        if (last) {
            const link = node.inwardLinksByIp[last.ipv6];
            let label = link.label;
            const curFormNum = Cjdnsplice.getEncodingForm(label, last.encodingScheme);
            if (curFormNum < formNum) {
                label = Cjdnsplice.reEncode(label, last.encodingScheme, formNum);
            }
            labels.push(label);
            hops.push({
                label: label,
                origLabel: link.label,
                scheme: last.encodingScheme,
                inverseFormNum: formNum
            });
            formNum = link.encodingFormNum;
        }
        last = node;
    });
    labels.push('0000.0000.0000.0001');
    const spliced = Cjdnsplice.splice.apply(null, labels);
    return { label: spliced, hops: hops };
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
const MAX_GLOBAL_CLOCKSKEW_MS = (1000 * 60 * 60 * 20);

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

const mkNode = (ctx, obj) => {
    if (typeof(obj.version) !== 'number') { throw new Error(); }
    if (typeof(obj.key) !== 'string') { throw new Error(); }
    if (typeof(obj.timestamp) !== 'string') { throw new Error(); }
    if (isNaN(Number('0x' + obj.timestamp))) { throw new Error(); }
    let encodingScheme;
    if (typeof(obj.encodingScheme) === 'undefined') {
        const onode = ctx.nodesByIp[obj.ipv6];
        if (onode && typeof(onode.encodingScheme) === 'object') {
            encodingScheme = onode.encodingScheme;
        } else {
            throw new Error("cannot create node we do not know it's encoding scheme");
        }
    } else {
        encodingScheme = obj.encodingScheme;
    }
    const out = Object.freeze({
        type: "Node",
        version: obj.version,
        key: obj.key,
        ipv6: Cjdnskeys.publicToIp6(obj.key),
        encodingScheme: encodingScheme,
        inwardLinksByIp: {},
        mut: {
            timestamp: obj.timstamp,
            announcements: [ ]
        }
    });
    if (obj.announcement) {
        out.mut.announcements[0] = obj.announcement;
    }
    return out;
};

const addNode = (ctx, node, overwrite) => {
    if (node.type !== "Node") { throw new Error(); }
    //if (!overwrite && ctx.nodesByKey[node.key]) { throw new Error(); }
    if (!overwrite && ctx.nodesByIp[node.ipv6]) { throw new Error(); }
    //ctx.nodesByKey[node.key] = node;
    ctx.nodesByIp[node.ipv6] = node;
    return node;
};

const logMsg = (ctx, bytes) => {
    let i = 0;
    const tryWrite = () => {
        try {
            ctx.log.write(bytes);
        } catch (e) {
            if (i++ > 10) {
                throw e;
            } else {
                console.log("failed write, trying again...");
                setTimeout(tryWrite, 2000);
            }
        }
    };
    tryWrite();
};

const propagateMsg = (ctx, bytes) => {
    const toWrite = new Buffer(8 + bytes.length);
    toWrite.writeUInt32BE(0x5f3759df, 0);
    toWrite.writeUInt32BE(bytes.length, 4);
    bytes.copy(toWrite, 8);
    logMsg(ctx, toWrite);
};

const handleAnnounce = (ctx, msg, fromNode, cjdnslink) => {
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
    if (ann) { node = ctx.nodesByIp[ann.nodeIp]; }

    if (ann && node && node.mut.timestamp > ann.timestamp) {
        console.log("old timestamp");
        replyError = "old_message";
        ann = undefined;
    }

    let maxClockSkew;
    if (fromNode) {
        maxClockSkew = MAX_CLOCKSKEW_MS;
        if (ann.snodeIp !== ctx.mut.selfNode.ipv6) {
            console.log("announcement meant for other snode");
            replyError = "wrong_snode";
            ann = undefined;
        }
    } else {
        maxClockSkew = MAX_GLOBAL_CLOCKSKEW_MS;
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

    const nodex = mkNode(ctx, {
        version: msg.contentBenc.p,
        key: ann.nodePubKey,
        encodingScheme: scheme,
        timestamp: ann.timestamp,
        announcement: ann
    });
    if (node) {
        if (node.mut.timestamp > ann.timestamp) {
            console.log("old announcement, drop");
            replyAnnounce(ctx, msg, node, cjdnslink);
            return;
        } else if (node.version !== nodex.version) {
            console.log("version change, replacing node");
            node = addNode(ctx, nodex, true);
        } else if (JSON.stringify(node.encodingScheme) !== JSON.stringify(nodex.encodingScheme)) {
            console.log("encodingScheme change, replacing node");
            node = addNode(ctx, nodex, true);
        } else if (ann.isReset) {
            console.log("reset message");
            node = addNode(ctx, nodex, true);
        } else {
            addAnnouncement(node, ann);
        }
    } else {
        node = addNode(ctx, nodex, false);
    }

    ann.peers.forEach((peer) => {
        const ipv6 = peer.ipv6;
        if (peer.label === '0000.0000.0000.0000' && node.inwardLinksByIp[ipv6]) {
            delete node.inwardLinksByIp[ipv6];
            ctx.mut.dijkstra = undefined;
            return;
        }
        const stored = node.inwardLinksByIp[ipv6];
        const newLink = node.inwardLinksByIp[ipv6] = mkLink(peer, ann);
        if (!stored) {
        } else if (newLink.label !== stored.label) {
        } else if (linkValue(newLink) !== linkValue(stored)) {
        } else {
            return;
        }
        ctx.mut.dijkstra = undefined;
    });

    propagateMsg(ctx, ann.binary);
    replyAnnounce(ctx, msg, node, cjdnslink);
};

const onSubnodeMessage = (ctx, msg, cjdnslink) => {
    if (!msg.contentBenc.sq) { return; }
    console.log(msg.contentBenc.sq.toString('utf8'));
    if (msg.contentBenc.sq.toString('utf8') === 'gr') {
        const srcIp = Cjdnskeys.ip6BytesToString(msg.contentBenc.src);
        const tarIp = Cjdnskeys.ip6BytesToString(msg.contentBenc.tar);
        const src = ctx.nodesByIp[srcIp];
        const tar = ctx.nodesByIp[tarIp];
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
        cjdnslink.send(msg);
    } else if (msg.contentBenc.sq.toString('utf8') === 'ann') {
        handleAnnounce(ctx, msg, true, cjdnslink);
    } else {
        console.log(msg.contentBenc);
    }
};

const service = (ctx) => {
    let cjdns;
    nThen((waitFor) => {
        Cjdnsadmin.connectWithAdminInfo(waitFor((c) => { cjdns = c; }));
    }).nThen((waitFor) => {
        // TODO: Need to replace this before we try running a supernode on a subnode.
        cjdns.RouterModule_getPeers("0000.0000.0000.0001", waitFor((err, ret) => {
            if (err) { throw err; }
            const nodeID = ret.peers[0];
            let version;
            const key = nodeID.replace(/^v([0-9]+)\.0000\.0000\.0000\.0001\./, (all, v) => {
                version = Number(v);
                return '';
            });
            if (isNaN(version) || key === nodeID) {
                throw new Error("invalid nodeID [" + nodeID + "]");
            }
            const ipv6 = Cjdnskeys.publicToIp6(key);
            ctx.nodesByIp[ipv6] = ctx.mut.selfNode = mkNode(ctx, {
                version: version,
                key: key,
                ipv6: ipv6,
                encodingScheme: ret.encodingScheme,
                inwardLinksByIp: {},
                timestamp: 'ffffffffffffffff'
            });
            console.log("Got selfNode");
        }));
    }).nThen((waitFor) => {
        Cjdnsniff.sniffTraffic(cjdns, 'CJDHT', waitFor((err, cjdnslink) => {
            console.log("Connected to cjdns engine");
            if (err) { throw err; }
            cjdnslink.on('error', (e) => {
                console.error('sniffTraffic error');
                console.error(e.stack);
            });
            cjdnslink.on('message', (msg) => {
                onSubnodeMessage(ctx, msg, cjdnslink);
            });
        }));
    });
};

const Http = require('http');
const testSrv = (ctx) => {
    Http.createServer((req, res) => {
        const ents = req.url.split('/');
        ents.shift();
        if (ents[0] === 'path') {
            ents.shift();
            //res.end(JSON.stringify(ents));
            const srcIp = ents[0];
            const tarIp = ents[1];
            const src = ctx.nodesByIp[srcIp];
            const tar = ctx.nodesByIp[tarIp];
            console.log("getRoute req " + srcIp + " " + tarIp);
            if (!src) { res.end("src not found"); return; }
            if (!tar) { res.end("tar not found"); return; }
            const r = getRoute(ctx, src, tar);
            res.end(JSON.stringify(r, null, '  '));
        } else {
            //console.log(req.url);
            res.end(req.url);
        }
    }).listen(3333);
};

const MS_MINUTE = 1000 * 60;
const KEEP_TABLE_CLEAN_CYCLE = 3 * MS_MINUTE;
const EXPIRATION_TIME = 10 * MS_MINUTE;
const keepTableClean = (ctx) => {
    setInterval(() => {
        console.log("keepTableClean()");
        const minTime = now() - EXPIRATION_TIME;
        for (const nodeIp in ctx.nodesByIp) {
            const node = ctx.nodesByIp[nodeIp];
            const n = now();
            if (minTime > Number(node.timestamp)) {
                console.log("forgetting node [" + nodeIp + "]");
                delete ctx.nodesByIp;
                continue;
            }
            for (const peerIp in node.inwardLinksByIp) {
                console.log("forgetting link [" + nodeIp + "]<-[" + peerIp + "]");
                const peer = node.inwardLinksByIp[peerIp];
                if (minTime > peer.time) {
                    delete node.inwardLinksByIp[peerIp];
                }
            }
        }
    }, KEEP_TABLE_CLEAN_CYCLE);
};

const main = () => {
    const confIdx = process.argv.indexOf('--config');
    if (confIdx > -1) { Config = require(process.argv[confIdx+1]); }

    let ctx = Object.freeze({
        //nodesByKey: {},
        //ipnodes: {},
        nodesByIp: {},
        clients: [],
        mut: {
            dijkstra: undefined,
            selfNode: undefined
        }
    });

    keepTableClean(ctx);

    //if (Config.backboneBind) { backbone(ctx); }
    if (Config.serviceBind) { service(ctx); }
    testSrv(ctx);
    //if (Config.walkerCycle) { setupWalker(ctx); }
    //if (Config.connectTo.length) { connectOut(ctx); }
};
main();
