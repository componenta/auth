<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

/**
 * Represents a user that participates in session-based authentication.
 *
 * Provides access to the current session identifier and
 * the collection of all active sessions for this user.
 *
 * To retrieve the full session object: $session = $user->sessions->find($user->currentSessionId);
 */
interface SessionAwareInterface
{
    /**
     * The ID of the session that authenticated the current request.
     *
     * Null when no session is associated with the current request.
     */
    public ?string $currentSessionId { get; set; }

    /**
     * All active sessions belonging to this user.
     */
    public SessionCollectionInterface $sessions { get; }
}
