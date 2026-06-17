<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

/**
 * Internal marker used to roll back a regeneration transaction when
 * the optimistic lock on the old session is lost to a concurrent request.
 *
 * Never surfaces to callers - {@see DatabaseSessionManager::regenerate()}
 * catches it and follows the replacement chain instead.
 */
final class ConcurrentRegenerationException extends \RuntimeException
{
}
