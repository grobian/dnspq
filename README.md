dnspq
=====

DNS Parallel Quering library.

The objective of DNSpq is to query multiple DNS servers in parallel when
trying to resolve a query.  The pq in DNSpq hence stands for Parallel
Query.  Querying multiple servers in parallel is non-standard and
aggressive towards nameservers, so not suited for use other than for a
specific use-case, whis is most likely constrained to a local area
network and dedicated DNS servers.

DNSpq queries (in parallel) multiple DBS servers and takes the first
answer back to the client.  But DNSpq is not just doing that, it tries
to be smart in what it does, when dealing with multiple servers to make
the setup as resilient and robust as possible.  The characteristics of
DNSpq are:

- Each query is sent to all servers at the same time
- The total waiting time for such a request is 500ms (half a second)
- Each query is retried once, in case of no response within 300ms
- Failure responses are considered no responses, hence additional
  responses are waited for
- As soon as a successful response is received, that response is
  returned to the caller

As a consequence of above, broken or unavailable servers responding that
way don't cause failure responses per definition, in most cases other
responses are positive, such as when a server gets restarted.  The
client becomes greedy as well, since it asks for more than it is willing
to retrieve, but this is all to improve the overal response time in case
of server failure or downtime.

DNSpq doesn't have a cache.  It only supports A-type queries, and simple
responses to those.  The library, which is wrapped in a nss module
(`libnss_dnspq.so.2`) aborts on any attempt to do something which is not
a simple A-type query, and a simple response to that.  This makes it
easy to have the library fallback queries to the normal glibc resolver.


Author
------
Fabian Groffen


Acknowledgement
---------------
This library was originally developed for Booking.com.  With approval
from Booking.com, the code was generalised and published as Open Source
on github, for which the author would like to express his gratitude.
