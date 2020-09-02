.. _performance:
.. include:: references.rst

*************
Performance
*************

Requesting permissions for a specific user and service can be demanding if a lot of
requests are done rapidly. `PostgreSQL`_ and `SQLAlchemy`_ are usually fast enough, but
when more than a couple requests per second are needed, some solutions are possible to
improve the performance of these requests.

We can take advantage of the fact that permission are not susceptible to change often
and cache the results of these permission queries.

While not activated by default, it's possible to cache the access control lists (ACLs)
for all services, and give it an expiration timeout::

  # example Paste Deploy configuration
  cache.regions = acl
  cache.type = memory
  cache.acl.expire = 5  # seconds

For a particular request that queries a user's ACL
for a specific service, the response will be cached for 5 seconds. The consequence of this
caching is that any permission change will take 5 seconds to be effective. Depending on the
use case, this can be perfectly acceptable and the performance improvement is not negligible.
You should test and profile for your particular environment.
