/*
 *  This file is part of dnspq.
 *
 *  dnspq is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  dnspq is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with dnspq.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <netdb.h>

const char *pools[] = {
    "xxxx",
    "yyyy",
    "zzzz"
};
const char domain[] = ".some-pool";
const size_t poolsnr = sizeof(pools) / sizeof(*pools);

int main() {
	struct hostent *he;
	char pool[256];
	int last_addr = 0;
	int i;
	size_t dups = 0;

	for (i = 0; i < 100000; i++) {
		snprintf(pool, sizeof(pool), "%s%s", pools[i % poolsnr], domain);
		if ((he = gethostbyname(pool)) != NULL) {
			if (*((int *)he->h_addr) == last_addr)
				dups++;
			last_addr = *((int *)he->h_addr);
		} else {
			printf("error resolving %s\n", pool);
		}
	}
	printf("dups: %zd\n", dups);

	return 0;
}
