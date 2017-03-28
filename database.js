/*@flow*/
const Pg = require('pg');
/*::const ConfigType = require('./config.example.js');*/

const NOFUNC = ()=>{};

const addMessage = (ctx, nodeIp, annHash, timestamp, annBin, peersIp6, cb) => {
    const args = [ nodeIp, annHash, timestamp, annBin, peersIp6 ];
    ctx.db.query('SELECT Snode_addMessage($1, $2, $3, $4, $5)', args, (err, ret) => {
        if (err) { throw err; }
        cb();
    });
};

const garbageCollect = (ctx, minTs, cb) => {
    const q = ctx.db.query('SELECT Snode_garbageCollect($1)', [ minTs ]);
    q.on('error', (err) => { throw err; });
    q.on('end', cb);
};

const getMessage = (ctx, hash, cb) => {
    ctx.db.query('SELECT mc.content FROM messages AS me, messageContent AS mc ' +
        'WHERE me.hash = $1 AND me.id = mc.id', [ hash ], (err, ret) => {
            if (err) { throw err; }
            cb(ret.rows.length ? ret.rows[0].content : undefined);
        });
};

const deleteMessage = (ctx, hash, cb) => {
    ctx.db.query('SELECT Snode_deleteMessage($1)', [ hash ], (err, ret) => {
        if (err) { throw err; }
        cb();
    });
};

const getMessageHashes = (ctx, hashCb, doneCb) => {
    const q = ctx.db.query('SELECT hash FROM messages');
    q.on('error', (err) => { throw err; });
    q.on('row', (r) => { hashCb(r.hash); });
    q.on('end', doneCb);
};

const getAllMessages = (ctx, msgCb, doneCb) => {
    const q = ctx.db.query('SELECT content FROM messageContent');
    q.on('error', (err) => { throw err; });
    q.on('row', (r) => { msgCb(r.content); });
    q.on('end', doneCb);
};

module.exports.create = (config /*:ConfigType*/) => {
    config.postgres = config.postgres || {};
    config.postgres.user = config.postgres.user || 'cjdnsnode_user';
    config.postgres.database = config.postgres.database || 'cjdnsnode';
    config.postgres.password = config.postgres.password || 'cjdnsnode_passwd';
    config.postgres.host = config.postgres.host || 'localhost';
    config.postgres.port = config.postgres.port || 5432;

    const db = new Pg.Client(config.postgres);
    const ctx = Object.freeze({
        db: db
    });
    db.connect();
    return {
        _db: db,
        addMessage: (
            nodeIp /*:string*/,
            annHash /*:string*/,
            timestamp /*:number*/,
            annBin /*:Buffer*/,
            peersIp6 /*:Array<string>*/,
            cb /*:()=>void*/
        ) => {
            addMessage(ctx, nodeIp, annHash, timestamp, annBin, peersIp6, cb);
        },
        deleteMessage: (hash /*:string*/, cb /*:()=>void*/) => {
            deleteMessage(ctx, hash, cb);
        },
        garbageCollect: (minTs /*:number*/, cb /*:()=>void*/) => {
            garbageCollect(ctx, minTs, cb);
        },
        getMessage: (hash /*:string*/, cb /*:(?Buffer)=>void*/) => {
            getMessage(ctx, hash, cb);
        },
        getMessageHashes: (hashCb /*:(string)=>void*/, doneCb /*:()=>void*/) => {
            getMessageHashes(ctx, hashCb, doneCb);
        },
        getAllMessages: (msgCb /*:(Buffer)=>void*/, doneCb /*:()=>void*/) => {
            getAllMessages(ctx, msgCb, doneCb);
        },
        disconnect: (cb /*:()=>void*/) => {
            db.end((err) => {
                if (err) { throw err; }
                //console.log('disconnected');
                cb();
            });
        }
    };
};
