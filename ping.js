#!/usr/bin/env node
/* -*- Mode:js */
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
const Saferphore = require('saferphore');
const Bencode = require('bencode');
const Cjdns = require('cjdnsadmin');
const nThen = require('nthen');
const Cjdnskeys = require('cjdnskeys');

const MYIP6 = Cjdnskeys.publicToIp6('3fdqgz2vtqb0wx02hhvx3wjmjqktyt567fcuvj3m72vw5u6ubu70.k');

const now = () => new Date().getTime();

const pingNode = (cjdns, pingSem, addr, attempt, cb) => {
    pingSem.take((returnAfter) => {
        cjdns.RouterModule_pingNode(addr, 6000, returnAfter((err, ret) => {
            if (err) { throw err; }
            if (ret.result === 'timeout') {
                if (attempt < 16) {
                    pingNode(cjdns, pingSem, addr, attempt+1, cb);
                } else {
                    console.log(addr + ' TIMEOUT ' + ret.ms + 'ms');
                    cb();
                }
                return;
            }
            cb();
            if (ret.result !== 'pong') { console.log(ret); return; }
            console.log(ret.addr + ' PONG ' + ret.ms + 'ms');
        }));
    });
};

const run = (dat, verbose) => {
    const usock = Udp.createSocket('udp6');
    const sem = Saferphore.create(20);
    const handlers = [];
    usock.on('message', (msg, rinfo) => {
         //console.log('Received %d bytes from %s:%d\n', msg.length, rinfo.address, rinfo.port);
         //console.log(msg.toString('utf8'));
         const data = Bencode.decode(msg, 'utf8');
         (handlers[Number(data.txid)] || ()=>{})(data);
    });
    usock.bind(9002);
    const pingSem = Saferphore.create(5);

    let cjdns;
    nThen((waitFor) => {
        Cjdns.connectWithAdminInfo(waitFor((c) => { cjdns = c; }));
    }).nThen((waitFor) => {
        dat.forEach((arr, i) => {
            const nodeIp6 = Cjdnskeys.publicToIp6(arr[2]);
            if (nodeIp6 === MYIP6) { return; }
            sem.take((returnAfter) => {
                const msg = { 'q':'gr', 'src': MYIP6, 'tar': nodeIp6, 'txid':String(i) };
                const buff = Bencode.encode(msg);
                let attempts = 0;
                let send = () => {
                    if (attempts++ > 6) { throw new Error("snode unavailable"); }
                    usock.send(buff, 0, buff.length, 9001, '::1');
                };
                send();
                let inter = setInterval(send, 5000);
                const startTime = now();
                handlers[i] = returnAfter(waitFor((data) => {
                    clearTimeout(inter);
                    if (data.error) {
                        console.log(dat[i][0] + '.XXXX.XXXX.XXXX.XXXX.' + dat[i][2] + ' NO_PATH');
                        //console.log(data);
                        return;
                    } else if (verbose) {
                        console.log("pinging " + data.label);
                    }
                    dat[i][1] = data.label;
                    //console.log( dat[i].join('.') + ' ' + (now() - startTime) );
                    pingNode(cjdns, pingSem, dat[i].join('.'), 0, waitFor());
                }));
            });
        });
    }).nThen((waitFor) => {
        console.log('done');
        usock.close();
        cjdns.disconnect();
    });
};

const runAll = () => {
    const inData = [];
    let timeOfLastData = now();
    const sock = Net.connect(9001, '::1', () => {
        sock.on('data', (dat) => {
            timeOfLastData = now();
            inData.push(dat.toString('utf8'));
        });
        const intr = setInterval(() => {
            if (now() - timeOfLastData > 2000) {
                clearTimeout(intr);
                sock.end();
                const dat = inData.join('')
                    .split('\n')
                    .filter((x) => (!x.indexOf('["node"')))
                    .map(JSON.parse)
                    .map((x) => ([x[1], null, x[2]]));
                run(dat);
            }
        }, 500);
    });
};

const main = (args) => {
    const arg = args.pop();
    if (arg === '--all') {
        runAll();
        return;
    }

    let ver;
    let key;
    arg.replace(/^(v[0-9]+)\.([0-9a-f\.]{20})?([a-z0-9]{52}\.k)$/, (a,v,l,k)=>{ver = v; key = k;});

    if (!ver || !key) {
        console.log("Usage: ping v<version>.<cjdns public key>.k   ## Ping one node");
        console.log("Usage: ping --all                             ## Ping every node");
        return;
    }

    run([[ver, null, key]], true);
};
main(process.argv.slice(0));
