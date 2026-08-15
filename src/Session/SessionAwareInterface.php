<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

/** Exposes all active sessions associated with an identity. */
interface SessionAwareInterface
{
    public SessionCollectionInterface $sessions { get; }
}
