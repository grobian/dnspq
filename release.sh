#!/usr/bin/env bash

nr=$(grep VERSION dnspq.h | sed 's/^[^"]\+"\([0-9.]\+\)\".*$/\1/')
test `git diff | wc -l` -eq 0 \
	&& git tag v${nr} \
	&& git archive --format=tar.gz --prefix=dnspq-${nr}/ v${nr} > dnspq-${nr}.tar.gz
