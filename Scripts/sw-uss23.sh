#!/usr/bin/env bash

HERE=$(cd `dirname $0`; pwd)
SPDZROOT=$HERE/..

rm -f $HERE/../logs/*

export PLAYERS=3

. $HERE/run-common.sh

run_player sw-uss23-ring-party.x $* || exit 1
