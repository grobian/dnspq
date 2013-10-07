#!/usr/bin/env bash

nr=$(grep VERSION dnspq.h | sed 's/^[^"]\+"\([0-9.]\+\)\".*$/\1/')
git archive --format=tar.gz --prefix=dnspq-${nr}/ v${nr} > dnspq-${nr}.tar.gz
