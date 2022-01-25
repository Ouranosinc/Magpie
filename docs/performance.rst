.. include:: references.rst
.. _performance:

*************
Performance
*************

Requesting permissions for a specific :term:`User` and :term:`Service` can be demanding if a lot of
requests are execute in rapid succession. `PostgreSQL`_ and `SQLAlchemy`_ are usually fast enough, but
when more than a couple requests per second are needed, some solutions are possible to
improve the performance of these requests by avoiding unnecessary reload of static data.

We can take advantage of the fact that individual :term:`Permission` and :term:`Service` definitions are not
susceptible to change often and cache the results of these queries.

While not activated by default, it's possible to cache the :term:`Access Control List` (ACL) and :term:`Service`
retrieval operations for all services, and give it an expiration timeout.

.. code-block:: ini

    # example Paste Deploy configuration
    cache.regions = acl
    cache.type = memory
    cache.acl.expire = 5  # seconds

.. warning::
    Take into consideration that settings must be applied to `Twitcher`_ INI file such that incoming proxy requests
    will be effective in its web application, in turn using the :class:`magpie.adapter.MagpieAdapter`. Caching settings
    defined in `Magpie` INI file will be employed only when requesting
    :term:`Effective Permissions <Effective Permission>` resolution using `Magpie`'s API endpoints.


In the above example, for a particular request that queries a :term:`Logged User`'s ACL for a specific :term:`Service`,
the response will be cached for 5 seconds. The consequence of this caching is that any change to that specific
:term:`Permission` will take 5 seconds to be effective. Depending on the use case, this can be perfectly acceptable
and the performance improvement is not negligible. You should test and profile for your particular environment.

.. versionadded:: 3.7

    As of this version, additional handling of cache invalidation is introduced in some cases where it can be resolved.
    For example, calling a :term:`Service` update will invalidate the corresponding caches and should make the next
    request fetch the real definitions from database instead of cached ones.

.. warning::
    Take into consideration that caching on `Twitcher`_ side will still not affect `Magpie` side caching as they run on
    two separate web applications. Therefore, `Twitcher`_ could still indicate a different result than `Magpie` if the
    :term:`Service` definition was recently updated (cache is invalidated only in `Magpie`), but still not effective
    from `Twitcher`_ side (proxy requests).
