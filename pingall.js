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

const MYKEY = '3fdqgz2vtqb0wx02hhvx3wjmjqktyt567fcuvj3m72vw5u6ubu70.k';

const now = () => new Date().getTime();

const run = (data) => {
    const dat = data.split('\n')
        .filter((x) => (!x.indexOf('["node"')))
        .map(JSON.parse)
        .map((x) => ([x[1], null, x[2]]));
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
    Cjdns.connectWithAdminInfo((cjdns) => {
        dat.forEach((arr, i) => {
            if (arr[2] === MYKEY) { return; }
            sem.take((returnAfter) => {
                const msg = { 'q':'gr', 'src': MYKEY, 'tar': arr[2], 'txid':String(i) };
                const buff = Bencode.encode(msg);
                let attempts = 0;
                let send = () => {
                    if (attempts++ > 6) { throw new Error("unreachable"); }
                    usock.send(buff, 0, buff.length, 9001, '::1')
                };
                send();
                let inter = setInterval(send, 5000);
                const startTime = now();
                handlers[i] = returnAfter(function (data) {
                    clearTimeout(inter);
                    if (data.error) {
                        console.log(dat[i][0] + '.XXXX.XXXX.XXXX.XXXX.' + dat[i][2] + ' NO_PATH');
                        //console.log(data);
                        return;
                    }
                    dat[i][1] = data.label;
                    //console.log( dat[i].join('.') + ' ' + (now() - startTime) );
                    pingSem.take((returnAfter) => {
                        cjdns.RouterModule_pingNode(dat[i].join('.'), 6000, returnAfter((err, ret) => {
                            if (err) { throw err; }
                            if (ret.result === 'timeout') {
                                console.log(dat[i].join('.') + ' TIMEOUT ' + ret.ms + 'ms');
                                return
                            }
                            if (ret.result !== 'pong') { console.log(ret); return; }
                            console.log(ret.addr + ' PONG ' + ret.ms + 'ms');
                        }));
                    });
                });
            });
        });
    });
};

const main = () => {
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
                run(inData.join(''));
            }
        }, 500);
    });
};
main();
