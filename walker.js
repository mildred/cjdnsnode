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
var Cjdns = require('cjdnsadmin');
var Saferphore = require('saferphore');
var Cjdnsplice = require('cjdnsplice');
var nThen = require('nthen');

var getPeers = function (ctx, nodeName, near, cb) {
    ctx.sem.take(function (returnAfter) {
        console.log("getPeers near " + near);
        ctx.cjdns.RouterModule_getPeers(nodeName, 6000, near, returnAfter(function (err, ret) {
            if (err) { throw err; }
            console.log(JSON.stringify(ret));
            cb(ret);
        }));
    });
};

var splitName = function (name) {
    var out = { v: 0, label: '', key: '' };
    name.replace(/^(v[0-9]+)\.([0-9a-f\.]{19})\.([^\.]+\.k)$/, function (all, v, l, k) {
        out.v = v;
        out.label = l;
        out.key = k;
    });
    if (out.label === '') { throw new Error(name); }
    return out;
};

var getPeersOf = function (ctx, nodeName, cb) {
    var peers = [];
    var scheme;
    var key = splitName(nodeName).key;
    var again = function (near, count) {
        if (ctx.nodes[key]) { cb('already_checked'); return; }
        getPeers(ctx, nodeName, near, function (ret) {
            if (ret.error !== 'none') {
                throw new Error(JSON.stringify(ret));
            }
            if (ret.result === 'timeout') {
                if (count > 2) {
                    console.error('timeout');
                    cb('timeout');
                } else {
                    again(near, count+1);
                }
                return;
            } else if (ret.result !== 'peers') {
                throw new Error(JSON.stringify(ret));
            }
            scheme = ret.encodingScheme;
            peers.push.apply(peers, ret.peers);
            if (ret.peers.length === 8) {
                const nonCannonicalLabel = splitName(ret.peers[7]).label;
                const cannonicalLabel =
                    Cjdnsplice.reEncode(nonCannonicalLabel, scheme, Cjdnsplice.FORM_CANNONICAL);
                again(cannonicalLabel, 0);
            } else {
                var label = splitName(nodeName).label;
                var prs = {};
                peers = peers.map(function (p) {
                    var spl = splitName(p);
                    if (spl.label === '0000.0000.0000.0001') { return null; }
                    prs[spl.key] =
                        Cjdnsplice.reEncode(spl.label, scheme, Cjdnsplice.FORM_CANNONICAL);
                    spl.label = Cjdnsplice.splice(spl.label, label);
                    //console.log(spl.label);
                    if (spl.label === 'ffff.ffff.ffff.ffff') { return null; }
                    return spl.v + '.' + spl.label + '.' + spl.key;
                });
                peers = peers.filter(function (x, i) { return x && peers.indexOf(x) === i; });
                //console.log(prs);
                cb(undefined, {
                    peers: prs,
                    encodingScheme: scheme,
                    name: nodeName
                }, peers);
            }
        });
    };
    eval(ctx.magic);
};

const now = () => (new Date().getTime());

var doWalk = function (ctx, nodeName, cb) {
    getPeersOf(ctx, nodeName, function (err, node, peers) {
        var sn = splitName(nodeName);
        if (err || ctx.nodes[sn.key]) { cb(); return; }
        ctx.nodes[sn.key] = node;
        const lines = [ ['node', sn.v, sn.key, node.encodingScheme, now()] ];
        for (var k in node.peers) {
            lines.push(['link', sn.key, node.peers[k], k, now()]);
        }
        ctx.nodeUpdateHandler(lines);

        nThen(function (waitFor) {
            peers.forEach(function (pn) {
                //console.log(' ' + pn);
                var pnk = splitName(pn).key;
                if (ctx.nodes[pnk]) { return; }
                doWalk(ctx, pn, waitFor());
            });
        }).nThen(cb);
    });
};

const mkCtx = (magic, nodeUpdateHandler, cb) => {
    Cjdns.connectWithAdminInfo(function (cjdns) {
        cb(Object.freeze({
            nodeUpdateHandler: nodeUpdateHandler || ()=>{},
            cjdns: cjdns,
            sem: Saferphore.create(32),
            nodes: {},
            magic: magic
        }));
    });
};

const walk = module.exports.walk = (magic, nodeUpdateHandler, cb) => {
    mkCtx(magic, nodeUpdateHandler, (ctx) => {
        ctx.cjdns.RouterModule_getPeers("0000.0000.0000.0001", function (err, ret) {
            if (err) { throw err; }
            doWalk(ctx, ret.peers[0], function () {
                //console.log(JSON.stringify(nodes, null, '  '));
                ctx.cjdns.disconnect();
                cb();
            });
        });
    });
};

const peersOf = module.exports.peersOf = (magic, nodeName, cb) => {
    mkCtx(magic, null, (ctx) => (getPeersOf(ctx, nodeName, (err, ret, peers) => {
        ctx.cjdns.disconnect();
        cb(err, ret, peers);
    })));
};
