<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Extracts session attributes (IP, User-Agent, device metadata)
 * from an HTTP request for use with {@see SessionManagerInterface::create()}.
 */
interface SessionAttributeExtractorInterface
{
    /**
     * @return array<string, string>
     */
    public function extract(ServerRequestInterface $request): array;
}
