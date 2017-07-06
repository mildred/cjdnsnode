/* @flow */
// vim: sts=4:sw=4:et:ts=4
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

package main

import (
	"cjdnsplice"
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"time"
	/*
	   const Fs = require('fs');
	   const Net = require('net');
	   const Udp = require('dgram');
	   const Crypto = require('crypto');
	   const nThen = require('nthen');
	   const Dijkstra = require('node-dijkstra');
	   const Cjdnsplice = require('cjdnsplice');
	   const Cjdnskeys = require('cjdnskeys');
	   const Cjdnsniff = require('cjdnsniff');
	   const Cjdnsadmin = require('cjdnsadmin');
	   const Cjdnsann = require('cjdnsann');
	   const Http = require('http');

	   const Database = require('./database');
	   const Peer = require('./peer');
	*/)

const (
	KeepTableCleanCycle = 4 * 60 * time.Minute
	AgreedTimeout       = 10 * time.Minute
	MaxClocksckew       = 10 * time.Second
	MaxGlobalClockskew  = 60 * 60 * 20 * time.Second
	GlobalTimeout       = MaxGlobalClockskew + AgreedTimeout
)

type any interface{}

type Link struct {
	Label           string
	MTU             any
	Drops           any
	Latency         any
	Penalty         any
	EncodingFormNum int
	Flags           uint64    `json:"flags"`
	Time            time.Time `json:"time"`
}

/*

const mkLink = (annPeer, ann) => {
	if (!ann) { throw new Error(); }
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

*/

func linkValue(link *Link) int {
	return 1
}

type Route struct {
	Label string   `json:"label"`
	Hops  []*Hop   `json:"hops"`
	Path  []string `json:"path"`
}

type Node struct {
	Version         int                       `json:"version"`
	Timestamp       time.Time                 `json:"timestamp"`
	Key             string                    `json:"key"`
	IPv6            string                    `json:"ipv6"`
	InwardLinksByIp map[string]*Link          `json:"inwardLinksByIp"`
	EncodingScheme  cjdnsplice.EncodingScheme `json:"encodingScheme"`
}

type Config struct {
	ConnectCjdns bool     `json:"connectCjdns"`
	Peers        []string `json:"peers"`
}

type Ctx struct {
	NodesByIp map[string]*Node
	Clients   []any
	Version   int
	Config    *Config
	Db        *Database
	Peer      *Peer
	Mut       CtxMut
}

type CtxMut struct {
	RouteCache map[string]*Route
	Dijkstra   Dijkstra
	SelfNode   *Node
}

type Hop struct {
	Label          any `json:"label"`
	OrigLabel      any `json:"origLabel"`
	Scheme         any `json:"scheme"`
	InverseFormNum int `json:"inverseFormNum"`
}

func GetRoute(ctx *Ctx, src, dst *Node) (*Route, error) {
	if src == nil || dst == nil {
		return nil, nil
	}

	if src == dst {
		return &Route{
			Label: "0000.0000.0000.0001",
			Hops:  []*Hop{},
		}, nil
	}

	if ctx.Mut.Dijkstra == nil {
		ctx.Mut.RouteCache = map[string]*Route{}
		ctx.Mut.Dijkstra = NewDijkstra()
		for nip, n := range ctx.NodesByIp {
			links := n.InwardLinksByIp
			l := map[string]int{}
			for pip, link := range links {
				l[pip] = linkValue(link)
			}
			ctx.Mut.Dijkstra.AddNode(nip, l)
		}
	}

	if cachedEntry, ok := ctx.Mut.RouteCache[dst.IPv6+"|"+src.IPv6]; ok {
		return cachedEntry, nil
	}

	// we ask for the path in reverse because we build the graph in reverse.
	// because nodes announce own their reachability instead of announcing reachability of others.

	pathReverse, err := ctx.Mut.Dijkstra.Path(dst.IPv6, src.IPv6)
	if err != nil {
		return nil, err
	}
	if pathReverse == nil {
		ctx.Mut.RouteCache[dst.IPv6+"|"+src.IPv6] = nil
		return nil, nil
	}

	var path []string
	for _, item := range pathReverse {
		path = append([]string{item}, path...)
	}

	var last *Node
	var labels []string
	var hops []*Hop
	var formNum int

	for _, nip := range path {
		node := ctx.NodesByIp[nip]
		if last != nil {
			link := node.InwardLinksByIp[last.IPv6]
			label := link.Label
			curFormNum := cjdnsplice.GetEncodingForm(label, last.EncodingScheme)
			if curFormNum < formNum {
				label, err = cjdnsplice.ReEncode(label, last.EncodingScheme, formNum)
				if err != nil {
					return nil, err
				}
			}
			labels = append([]string{label}, labels...)
			hops = append(hops, &Hop{
				Label:          label,
				OrigLabel:      link.Label,
				Scheme:         last.EncodingScheme,
				InverseFormNum: formNum,
			})
			formNum = link.EncodingFormNum
		}
		last = node
	}
	labels = append([]string{"0000.0000.0000.0001"}, labels...)
	spliced := cjdnsplice.Splice(labels...)
	route := &Route{
		Label: spliced,
		Hops:  hops,
		Path:  path,
	}
	ctx.Mut.RouteCache[dst.IPv6+"|"+src.IPv6] = route
	return route, nil
}

func NodeAnnouncementHash(node *Node) []byte {
	var carry [64]byte
	/*
		if node != nil {
			for (let i = node.mut.announcements.length - 1; i >= 0; i--) {
				const hash = Crypto.createHash('sha512').update(carry);
				carry = hash.update(node.mut.announcements[i].binary).digest();
			}
			node.mut.stateHash = carry;
		}
	*/
	return carry[:]
}

/*
const peersFromAnnouncement = (ann) => {
	return (ann.entities.filter((x) => (x.type === 'Peer')) /*:Array<any>* / );
};

const encodingSchemeFromAnnouncement = (ann) => {
	const scheme /*:any* / = ann.entities.filter((x) => (x.type === 'EncodingScheme'))[0];
	return scheme ? scheme.scheme : undefined;
};

const versionFromAnnouncement = (ann) => {
	const ver /*:any* / = ann.entities.filter((x) => (x.type === 'Version'))[0];
	return ver ? ver.version : undefined;
};

const addAnnouncement = (ctx, node, ann, annHash) => {
	const time = Number('0x' + ann.timestamp);
	const sinceTime = time - AGREED_TIMEOUT_MS;
	const newAnnounce = [];
	const peersAnnounced = {};
	node.mut.announcements.unshift(ann);
	node.mut.announcements.forEach((a) => {
		if (Number('0x' + a.timestamp) < sinceTime) { return; }
		let safe = false;
		const peers = peersFromAnnouncement(a);
		for (let i = 0; i < peers.length; i++) {
			if (peersAnnounced[peers[i].ipv6]) { continue; }
			safe = true;
			peersAnnounced[peers[i].ipv6] = true;
		}
		if (safe) {
			newAnnounce.push(a);
		} else {
			ctx.peer.deleteAnn(annHash);
		}
	});
	node.mut.announcements.splice(0, node.mut.announcements.length);
	Array.prototype.push.apply(node.mut.announcements, newAnnounce);
};

// mkNode
func MakeNode(ctx *Ctx, obj *Node) *Node {
    var encodingScheme cjdnsplice.EncodingScheme = obj.EncodingScheme
    if encodingScheme == nil {
		onode := ctx.NodesByIp[obj.IPv6];
		if onoce != nil && onode.EncodingScheme != nil {
		    encodingScheme = onode.EncodingScheme
		}
			if (onode && typeof(onode.encodingScheme) === 'object') {
				encodingScheme = onode.encodingScheme;
			} else {
				throw new Error("cannot create node we do not know its encoding scheme");
			}

    }
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
				throw new Error("cannot create node we do not know its encoding scheme");
			}
		} else {
			encodingScheme = obj.encodingScheme;
		}
		const out = Object.freeze({
			type: "Node",
			version: obj.version,
			key: obj.key,
			ipv6: obj.ipv6,
			encodingScheme: encodingScheme,
			inwardLinksByIp: { },
			mut: {
				timestamp: obj.timestamp,
				announcements: [ ],
				stateHash: undefined
			}
		});
		if (obj.announcement) {
			out.mut.announcements[0] = obj.announcement;
		}
	return out
}

const addNode = (ctx, node, overwrite) => {
	if (node.type !== "Node") { throw new Error(); }
	//if (!overwrite && ctx.nodesByKey[node.key]) { throw new Error(); }
	if (!overwrite && ctx.nodesByIp[node.ipv6]) { throw new Error(); }
	//ctx.nodesByKey[node.key] = node;
	ctx.nodesByIp[node.ipv6] = node;
	return node;
};

*/

func handleAnnounce(ctx *Ctx, annBin any, fromNode, fromDb bool) {
}

/*
const handleAnnounce = (ctx, annBin, fromNode, fromDb) => {
	let ann;
	let replyError = 'none';
	const annHash = Crypto.createHash('sha512').update(annBin).digest('hex');
	//console.log("ann: " + annBin.toString('hex'));
	console.log("ann:" + annHash);
	try {
		ann = Cjdnsann.parse(annBin);
	} catch (e) {
		console.log("bad announcement [" + e.message + "]");
		replyError = "failed_parse_or_validate";
	}
	//console.log(ann);
	//console.log(+new Date());

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
		if (!ctx.mut.selfNode) { throw new Error(); }
		if (ann && ann.snodeIp !== ctx.mut.selfNode.ipv6) {
			console.log("announcement from peer which is one of ours");
			replyError = "wrong_snode";
			ann = undefined;
		}
	} else {
		maxClockSkew = MAX_GLOBAL_CLOCKSKEW_MS;
		if (!fromDb && ctx.mut.selfNode && ann && ann.snodeIp === ctx.mut.selfNode.ipv6) {
			console.log("announcement meant for other snode");
			replyError = "wrong_snode";
			ann = undefined;
		}
	}
	if (ann && Math.abs(new Date() - Number('0x' + ann.timestamp)) > maxClockSkew) {
		console.log("unacceptably large clock skew " +
			(new Date() - Number('0x' + ann.timestamp)));
		replyError = "excessive_clock_skew";
		ann = undefined;
	} else if (ann) {
		//console.log("clock skew " + (new Date() - Number('0x' + ann.timestamp)));
	}

	let scheme;
	if (ann && (scheme = encodingSchemeFromAnnouncement(ann))) {
	} else if (node) {
		scheme = node.encodingScheme;
	} else if (ann) {
		console.log("no encoding scheme");
		replyError = "no_encodingScheme";
		ann = undefined;
	}

	let version;
	if (ann && (version = versionFromAnnouncement(ann))) {
	} else if (node) {
		version = node.version;
	} else if (ann) {
		console.log("no version");
		replyError = "no_version";
		ann = undefined;
	}

	if (!ann) {
		return { stateHash: nodeAnnouncementHash(node), error: replyError };
	}

	if scheme == nil {
		onode := ctx.NodesByIp[ann.nodeIp];
		if onode != nil && onode.EncodingScheme != nil {
		    scheme = onode.EncodingScheme
		}
	}

	nodex := &Node{
		Type: "Node",
		Version: obj.version,
		Key: obj.key,
		IPv6: obj.ipv6,
		EncodingScheme: encodingScheme,
		InwardLinksByIp: { },
		Mut: {
			Timestamp: obj.timestamp,
			Announcements: [ ],
			StateHash: undefined
		}
	}
	//const nodex = mkNode(ctx, {
	//	version: version,
	//	key: ann.nodePubKey,
	//	encodingScheme: scheme,
	//	timestamp: ann.timestamp,
	//	ipv6: ann.nodeIp,
	//	announcement: ann
	//});
	if (node) {
		if (node.mut.timestamp > ann.timestamp) {
			console.log("old announcement, drop");
			return { stateHash: nodeAnnouncementHash(node), error: replyError };
		} else if (node.version !== nodex.version) {
			console.log("version change, replacing node");
			node = addNode(ctx, nodex, true);
		} else if (JSON.stringify(node.encodingScheme) !== JSON.stringify(nodex.encodingScheme)) {
			console.log("encodingScheme change, replacing node");
			node = addNode(ctx, nodex, true);
		} else if (ann.isReset) {
			console.log("reset message");
			node = addNode(ctx, nodex, true);
			console.log(node.mut.announcements.length + ' announcements');
		} else {
			addAnnouncement(ctx, node, ann, annHash);
		}
	} else {
		node = addNode(ctx, nodex, false);
	}

	const peersIp6 = [];
	peersFromAnnouncement(ann).forEach((peer) => {
		const ipv6 = peer.ipv6;
		peersIp6.push(ipv6);
		if (!node) { throw new Error(); }
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

	if (peersIp6.length) {
		if (!fromDb) {
			ctx.db.addMessage(
				ann.nodeIp,
				annHash,
				Number('0x'+ann.timestamp),
				annBin,
				peersIp6,
				() => {}
			);
		}
		ctx.peer.addAnn(annHash, ann.binary);
	}
	return { stateHash: nodeAnnouncementHash(node), error: replyError };
};

const onSubnodeMessage = (ctx, msg, cjdnslink) => {
	if (!msg.contentBenc.sq) { return; }
	if (!msg.routeHeader.version || !msg.routeHeader.publicKey) {
		console.log("message from " + msg.routeHeader.ip + " with missing key or version");
		return;
	}
	if (msg.contentBenc.sq.toString('utf8') === 'gr') {
		const srcIp = Cjdnskeys.ip6BytesToString(msg.contentBenc.src);
		const tarIp = Cjdnskeys.ip6BytesToString(msg.contentBenc.tar);
		const src = ctx.nodesByIp[srcIp];
		const tar = ctx.nodesByIp[tarIp];
		const logMsg = "getRoute req " + srcIp + " " + tarIp + "  ";
		const r = getRoute(ctx, src, tar);

		if (r) {
			console.log(logMsg + r.label);
			msg.contentBenc.n = Buffer.concat([
				Cjdnskeys.keyStringToBytes(tar.key),
				new Buffer(r.label.replace(/\./g, ''), 'hex')
			]);
			msg.contentBenc.np = new Buffer([1, tar.version]);
		} else {
			console.log(logMsg + "not found");
		}
		msg.contentBenc.recvTime = now();
		msg.routeHeader.switchHeader.labelShift = 0;

		delete msg.contentBenc.sq;
		delete msg.contentBenc.src;
		delete msg.contentBenc.tar;
		cjdnslink.send(msg);
	} else if (msg.contentBenc.sq.toString('utf8') === 'ann') {
		const reply = handleAnnounce(ctx, msg.contentBenc.ann, true, false);
		if (!ctx.mut.selfNode) { throw new Error(); }
		msg.contentBenc = {
			txid: msg.contentBenc.txid,
			p: ctx.mut.selfNode.version,
			recvTime: +new Date(),
			stateHash: reply.stateHash,
			error: reply.error
		};
		msg.routeHeader.switchHeader.labelShift = 0;
		console.log("reply: " + reply.stateHash.toString('hex'));
		cjdnslink.send(msg);
	} else if (msg.contentBenc.sq.toString('utf8') === 'pn') {
		msg.contentBenc.recvTime = now();
		msg.contentBenc.stateHash = new Buffer(new Array(64).fill(0));
		if (msg.routeHeader.ip in ctx.nodesByIp) {
			const n = ctx.nodesByIp[msg.routeHeader.ip];
			if (n.mut.stateHash) {
				msg.contentBenc.stateHash = n.mut.stateHash;
			}
		}
		msg.routeHeader.switchHeader.labelShift = 0;
		delete msg.contentBenc.sq;
		delete msg.contentBenc.src;
		delete msg.contentBenc.tar;
		cjdnslink.send(msg);
	} else {
		console.log(msg.contentBenc);
	}
};

*/

func service(ctx *Ctx) {
}

/*
/*::import type { Cjdnsniff_BencMsg_t } from 'cjdnsniff'* /
const service = (ctx) => {
	let cjdns;
	nThen((waitFor) => {
		Cjdnsadmin.connectWithAdminInfo(waitFor((c) => { cjdns = c; }));
	}).nThen((waitFor) => {
		cjdns.Core_nodeInfo(waitFor((err, ret) => {
			if (err) { throw err; }
			const parsedName = Cjdnskeys.parseNodeName(ret.myAddr);
			const ipv6 = Cjdnskeys.publicToIp6(parsedName.key);
			//ctx.mut.selfNode = mkNode(ctx, {
			//	version: parsedName.v,
			//	key: parsedName.key,
			//	ipv6: ipv6,
			//	encodingScheme: ret.encodingScheme,
			//	inwardLinksByIp: {},
			//	timestamp: 'ffffffffffffffff'
			//});
			ctx.Mut.SelfNode = &Node{
			    Type: "Node",
			    Version: parsedName.v,
			    Key: parsedName.key,
			    IPv6: ipv6,
			    EncodingScheme: ret.encodingScheme,
			    InwardLinksByIp: { },
			    Mut: {
				    Timestamp:  'ffffffffffffffff',
				    Announcements: [ ],
				    StateHash: nil,
			    }
			}
            if ctx.Mut.SelfNode.EncodingScheme == nil {
		        onode := ctx.NodesByIp[ipv6];
		        if onoce != nil && onode.EncodingScheme != nil {
		            ctx.Mut.SelfNode.encodingScheme = onode.EncodingScheme
		        }
		    }
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
				/*::msg = (msg:Cjdnsniff_BencMsg_t);* /
				onSubnodeMessage(ctx, msg, cjdnslink);
			});
		}));
	}).nThen((waitFor) => {
		setInterval(() => {
			cjdns.UpperDistributor_listHandlers(0, (err, ret) => {
				if (err) { throw err; }
				if (ret.error !== 'none') {
					throw new Error("from cjdns: " + ret.error);
				}
				if (!ret.handlers.length) {
					throw new Error("became disconnected for cjdns");
				}
			});
		}, 5000);
	});
};

*/
func testSrv(ctx *Ctx) {
	var server http.Server
	server.Addr = ":3333"
	server.Handler = http.HandlerFunc(reqHandler)
	ctx.Peer.RunServer(&server)
}

func reqHandler(res http.ResponseWriter, req *http.Request) {
	/*
		const ents = req.url.split('/');
		ents.shift();
		if (ents[0] === 'path') {
			ents.shift();
			//res.end(JSON.stringify(ents));
			const srcIp = ents[0];
			const tarIp = ents[1];
			const src = ctx.nodesByIp[srcIp];
			const tar = ctx.nodesByIp[tarIp];
			console.log("http getRoute req " + srcIp + " " + tarIp);
			if (!src) { res.end("src not found"); return; }
			if (!tar) { res.end("tar not found"); return; }
			const r = getRoute(ctx, src, tar);
			res.end(JSON.stringify(r, null, '  '));
		} else if (ents[0] === 'walk') {
			const out = [];
			const outLinks = [];
			for (const ip in ctx.nodesByIp) {
				const node = ctx.nodesByIp[ip];
				out.push([
					"node",
					Math.floor(Number('0x' + node.mut.timestamp) / 1000),
					"-",
					"v" + node.version + ".0000.0000.0000.0001." + node.key,
					node.encodingScheme
				]);
				for (const peerIp in node.inwardLinksByIp) {
					const link = node.inwardLinksByIp[peerIp];
					const otherNode = ctx.nodesByIp[peerIp];
					//if (!otherNode) { continue; }
					outLinks.push([
						otherNode ? "link" : "oldlink",
						Math.floor(link.time / 1000),
						"-",
						node.key,
						otherNode ? otherNode.key : peerIp,
						link.label,
						link.drops
					]);
				}
			}
			out.push.apply(out, outLinks);
			res.end(out.map((x)=>JSON.stringify(x)).join('\n'));
		} else {
			//console.log(req.url);
			res.end(req.url);
		}
	*/
}

func keepTableClean(c context.Context, ctx *Ctx) {
	for {
		c2, _ := context.WithTimeout(c, KeepTableCleanCycle)
		log.Println("keepTableClean()")
		minTime := time.Now().Add(-GlobalTimeout)
		for nodeIp, node := range ctx.NodesByIp {
			n := time.Now()
			_ = n
			if minTime.After(node.Timestamp) {
				log.Printf("keepTableClean() forgetting node [%s]", nodeIp)
				// TODO: WTF, js says: delete ctx.nodesByIp;
				delete(ctx.NodesByIp, nodeIp)
				continue
			}
		}
		<-c2.Done()
	}
}

func loadDb(ctx *Ctx) {
	log.Println("gc")
	minTs := time.Now().Add(-GlobalTimeout)
	ctx.Db.GarbageCollect(minTs)
	log.Println("Garbage collection complete")
	log.Println("gc3")
	for msgBytes := range ctx.Db.GetAllMessages() {
		handleAnnounce(ctx, msgBytes, false, true)
	}
	log.Println("messages loaded")
}

func getConfig(fname string, config *Config) error {
	f, err := os.Open(fname)
	if err != nil {
		return err
	}
	defer f.Close()

	return json.NewDecoder(f).Decode(config)
}

func main() {
	var configFile string
	var config Config

	flag.StringVar(&configFile, "config", "", "JSON configuration file")
	flag.Parse()

	if configFile != "" {
		if err := getConfig(configFile, &config); err != nil {
			log.Fatal(err)
		}
	}

	ctx := &Ctx{
		NodesByIp: map[string]*Node{},
		Clients:   []any{},
		Version:   1,

		Config: &config,
		Db:     nil,
		Peer:   nil,

		Mut: CtxMut{
			Dijkstra:   nil,
			SelfNode:   nil,
			RouteCache: map[string]*Route{},
		},
	}

	ctx.Db = NewDatabase(&dbNotifs{ctx}, &config)
	ctx.Peer = NewPeer(&peerNotifs{ctx})

	loadDb(ctx)

	//go keepTableClean(ctx);
	if config.ConnectCjdns {
		service(ctx)
	}
	testSrv(ctx)
	//TODO: ctx.peer.onAnnounce((peer, msg) => { handleAnnounce(ctx, msg, false, false); });
	for _, peer := range ctx.Config.Peers {
		ctx.Peer.ConnectTo(peer)
	}
}

type peerNotifs struct{ *Ctx }

func (ctx peerNotifs) HandleAnnounce(peer, msg any) {
	handleAnnounce(ctx.Ctx, msg, false, false)
}

type dbNotifs struct{ *Ctx }

func (ctx dbNotifs) Notification(msg interface{}) {
	log.Println(msg)
}

type Database struct{}
type Peer struct{}

func NewDatabase(notifs *dbNotifs, config *Config) *Database { return nil }
func NewPeer(notifs *peerNotifs) *Peer                       { return nil }

func (db *Database) GetAllMessages() <-chan any { return nil }
func (db *Database) GarbageCollect(t time.Time) {}

func (p *Peer) ConnectTo(ws_address string)   {}
func (p *Peer) RunServer(server *http.Server) {}
