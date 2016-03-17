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
const Dijkstra = require('node-dijkstra');
const Bencode = require('bencode');
const Cjdnsplice = require('./cjdnsplice');
const Walker = require('./walker');
let Config = require('./config');

const FLUSH_STATE_CYCLE = 30000;
const RECONNECT_CYCLE = 10000;

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
    buildGraph(ctx);
    const path = ctx.mut.dijkstra.path(src, dst);
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

const service = (ctx) => {
    const usock = Udp.createSocket('udp6');
    usock.on('message', (bytes, rinfo) => {
        try {
            const data = Bencode.decode(bytes, 'utf8');
            const route = { txid: data.txid };
            if ('q' in data && data.q === 'gr') {
                console.log(data);
                const r = getRoute(ctx, data.src, data.tar);
                if (r) {
                    route.label = r.label;
                } else {
                    route.error = "not_found";
                }
            }
            const buff = Bencode.encode(route);
            console.log(buff.toString('utf8'));
            usock.send(buff, 0, buff.length, rinfo.port, rinfo.address);
        } catch (e) { console.log(e.stack); }
        console.log('Received %d bytes from %s:%d\n', bytes.length, rinfo.address, rinfo.port);
    });
    usock.bind.apply(usock, Config.serviceBind);
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
        const again = () => {
            const data = {d:''};
            const sock = Net.connect(x, () => {
            });
            sock.on('data', (dat) => onData(ctx, data, dat, { write: (x) => console.log(x) }));
            sock.on('end', () => {
                console.log("connection " + JSON.stringify(x) + " lost");
                setTimeout(again, RECONNECT_CYCLE);
            });
        };
        again();
    });
};

const main = () => {
    const confIdx = process.argv.indexOf('--config');
    if (confIdx > -1) { Config = require(process.argv[confIdx+1]); }

    let ctx = Object.freeze({
        nodes: {},
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
