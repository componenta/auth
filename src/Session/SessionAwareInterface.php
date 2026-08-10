<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

/**
 * Exposes all active sessions that belong to an identity.
 *
 * The session that authenticated the current request is request-scoped and is
 * available as the SessionInterface PSR-7 request attribute. It must not be
 * stored as mutable state on a reusable identity object.
 */
interface SessionAwareInterface
{
    public SessionCollectionInterface $sessions { get; }
}
