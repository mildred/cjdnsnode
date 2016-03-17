#!/bin/bash
ps -ef | grep -v grep | grep -q 'server.js cjdnsnode' && exit 0;
node ./server.js cjdnsnode
