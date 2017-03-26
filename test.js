const nThen = require('nthen');
const Pg = require('pg');
const Database = require('./database');

const ANN = [
    "fc22:5cda:a8ca:22c4:cccd:d188:ae5e:76ed",
    "e6e51e3d5ccac09157e57af90ba1a7d3424087f82dd9d68e7b943989eaac6e41" +
    "e6edf1c611d69d98fb8164f5036548b09e69f8ccc12d8a3ffadd566cc2993388",
    "15b0afbc269",
    new Buffer(
        '155307319ad0974808563cdb5f0220726191df02d482dfc60f9b800f1bba7330' +
        '4dda4080cce9a0149bb5af30a186d39f7e1c16edc2e8be62e1e0b20b257e5706' +
        '0f45ba34b06f511a3051aea0267ba179cb7a0211e997b47c65caebb6a5c7e193' +
        'fc5071b5aebf7b7065770ec825429dd9000015b0afbc26990402001401070061' +
        '14458100200100000000fffffffffffffc557e0c74df47098b6443d6ee433c27' +
        '00000015200100000000fffffffffffffcbb5056899e2838f1ad12eb97041ff1' +
        '000000a6200100000000fffffffffffffc5071b5aebf7b7065770ec825429dd9' +
        '00000015', 'hex'),
    [
        "fc55:7e0c:74df:4709:8b64:43d6:ee43:3c27",
        "fcbb:5056:899e:2838:f1ad:12eb:9704:1ff1",
        "fc50:71b5:aebf:7b70:6577:0ec8:2542:9dd9"
    ]
];

const main = () => {
    const confIdx = process.argv.indexOf('--config');
    const config = require( (confIdx > -1) ? process.argv[confIdx+1] : './config' );
    const db = Database.create(config);
    nThen((waitFor) => {
        let empty = true;
        db.getMessageHashes((h) => {
            console.log(h);
            empty = false;
        }, waitFor(() => {
            if (!empty) {
                throw new Error(
                    "seems there are entries in the db, drop and re-init before using test.js"
                );
            }
        }));
    }).nThen((waitFor) => {
        db.deleteMessage(ANN[1], waitFor());
    }).nThen((waitFor) => {
        db.addMessage(ANN[0], ANN[1], ANN[2], ANN[3], ANN[4], waitFor());
    }).nThen((waitFor) => {
        let empty = true;
        db.getMessageHashes((h) => {
            if (h !== ANN[1]) { throw new Error(); }
            empty = false;
        }, waitFor(() => {
            if (empty) { throw new Error(); }
        }));
    }).nThen((waitFor) => {
        db.getMessage(ANN[1], waitFor((msg) => {
            if (msg.toString('base64') !== ANN[3].toString('base64')) { throw new Error(); }
        }));
    }).nThen((waitFor) => {
        db.deleteMessage(ANN[1], waitFor());
    }).nThen((waitFor) => {
        db.getMessageHashes((h) => { throw new Error(); }, waitFor());
    }).nThen((waitFor) => {
        db.addMessage(ANN[0], ANN[1], ANN[2], ANN[3], ANN[4], waitFor());
    }).nThen((waitFor) => {
        db.garbageCollect('1490537923178', waitFor());
    }).nThen((waitFor) => {
        db.getMessageHashes((h) => { throw new Error(); }, waitFor());
    }).nThen((waitFor) => {
        db.disconnect(waitFor());
    }).nThen((waitFor) => {
        console.log('looks ok');
    });
};
main();
