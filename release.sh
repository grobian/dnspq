#!/usr/bin/env bash

# This file is part of dnspq.
#
# dnspq is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# dnspq is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with dnspq.  If not, see <http://www.gnu.org/licenses/>.


nr=$(grep VERSION dnspq.h | sed 's/^[^"]\+"\([0-9.]\+\)\".*$/\1/')
test `git diff | wc -l` -eq 0 \
	&& git tag v${nr} \
	&& git archive --format=tar.gz --prefix=dnspq-${nr}/ v${nr} > dnspq-${nr}.tar.gz

test $? -eq 0 \
	&& echo "don't forget to git push && git push --tags" \
	|| echo "something went wrong, do you have uncommitted changes?"
