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

var CHAR_TO_BITS = {};
("0123456789abcdefABCDEF").split('').forEach(function (chr) {
    CHAR_TO_BITS[chr] = Number('0x1'+chr).toString(2).substring(1).split('').map((x)=>(Number(x)));
});

var labelToBits = module.exports.labelToBits = function (label) {
    var out = [];
    label = label.replace(/\./g, '');
    for (var i = 0; i < label.length; i++) {
        out.push.apply(out, CHAR_TO_BITS[label[i]]);
    }
    return out;
};

var bitsToChar = function (array) {
    var num = 0;
    for (var i = 0; i < 4; i++) {
        num |= (array.pop() << i);
    }
    return num.toString(16);
};

var bitsToLabel = module.exports.bitsToLabel = function (array) {
    array = array.slice(0);
    var chars = [];
    for (var i = 0; i < 16; i++) {
        if ((i % 4) === 0) { chars.unshift('.'); }
        chars.unshift(bitsToChar(array));
    }
    chars.pop();
    return chars.join('');
};

var errorArray = function () {
    return new Array(64).fill(1);
};

var spliceBits = module.exports.spliceBits = function (goHere, viaHere) {
    goHere = goHere.slice(0);
    viaHere = viaHere.slice(0);
    while (viaHere.shift() === 0) ;
    goHere.push.apply(goHere, viaHere);
    while (goHere.shift() === 0) ;
    goHere.unshift(1);
    if (goHere.length >= 60) { return errorArray(); }
    while (goHere.length < 64) { goHere.unshift(0); }
    return goHere;
};

var SCHEME_358 = module.exports.SCHEME_358 = [
    {"bitCount":8,"prefix":"00000000","prefixLen":2},
    {"bitCount":5,"prefix":"00000002","prefixLen":2},
    {"bitCount":3,"prefix":"00000001","prefixLen":1}
];

var splice = module.exports.splice = function (goHere, viaHere) {
    var result = spliceBits(labelToBits(goHere), labelToBits(viaHere));
    return bitsToLabel(result);
};

var getEncodingForm = module.exports.getEncodingForm = function (label, scheme) {
    var lstr = labelToBits(label).join();
    for (var i = 0; i < scheme.length; i++) {
        var pfxStr = labelToBits(scheme[i].prefix).join().substr(scheme[i].prefixLen * -1);
        if (lstr.endsWith(pfxStr)) { return i; }
    }
    return -1;
};

var fixLength = function (array, length) {
    while (array.length > length) {
        if (array.shift() !== 0) { throw new Error("length cannot be reduced"); }
    }
    while (array.length < length) { array.unshift(0); }
};

var reEncode = module.exports.reEncode = function (labelStr, scheme, desiredFormNum) {
    var formN = getEncodingForm(labelStr, scheme);
    if (formN < 0) { throw new Error("could not detect encoding form"); }
    if (!scheme[desiredFormNum]) { throw new Error("invalid desiredFormNum"); }
    var label = labelToBits(labelStr);
    var form = scheme[formN];
    var desiredForm = scheme[desiredFormNum];
    var dir = label.splice((form.bitCount + form.prefixLen) * -1);
    dir.splice(form.prefixLen * -1);
    fixLength(dir, desiredForm.bitCount);
    label.push.apply(label, dir);
    label.push.apply(label, labelToBits(desiredForm.prefix).splice(desiredForm.prefixLen * -1));
    fixLength(label, 60);
    fixLength(label, 64);
    return bitsToLabel(label);
};

const isOneHop = module.exports.isOneHop = (label, encodingScheme) => {
    const formNum = getEncodingForm(label, encodingScheme);
    if (formNum < 0) { throw new Error("not a valid label for the given scheme"); }
    const form = encodingScheme[formNum];
    const bits = form.bitCount + form.prefixLen;
    const labelBits = labelToBits(label);
    for (let i = 0; i < labelBits.length - bits - 1; i++) {
        if (labelBits[i]) { return false; }
    }
    return true;
};

// [ { labelP: "", key: "", encodingScheme: [], labelN: "" }, { ... }]
var buildLabel = module.exports.buildLabel = function (pathArray) {
    let path = [];
    pathArray.forEach(function (hop, i) {
        let labelN = hop.labelN;
        if (!labelN) {
            if (i < pathArray.length - 1) { throw new Error("every hop must have labelN"); }
            return;
        }
        if (hop.labelP) {
            let formP = getEncodingForm(hop.labelP, hop.encodingScheme);
            let formN = getEncodingForm(labelN, hop.encodingScheme);
            let bitsP = hop.encodingScheme[formP].bitCount + hop.encodingScheme[formP].prefixLen;
            let bitsN = hop.encodingScheme[formN].bitCount + hop.encodingScheme[formN].prefixLen;
            if (bitsP > bitsN) {
                labelN = reEncode(labelN, hop.encodingScheme, formP);
            }
        }
        path.push(labelN);
    });
    let rpath = path.slice(0).reverse();
    let result = labelToBits(rpath.shift());
    rpath.forEach(function (x) {
        //console.log(bitsToLabel(result) + '  ' + x);
        result = spliceBits(result, labelToBits(x));
        //console.log(bitsToLabel(result));
    });
    //console.log(result.join());
    return { label: bitsToLabel(result), path: path };
};
