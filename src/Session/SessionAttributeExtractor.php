<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Default implementation that extracts IP, User-Agent,
 * and device metadata (OS, browser, device type) from the request.
 */
final readonly class SessionAttributeExtractor implements SessionAttributeExtractorInterface
{
    public function __construct(
        private DeviceDetector $deviceDetector = new DeviceDetector(),
    ) {}

    #[\Override]
    public function extract(ServerRequestInterface $request): array
    {
        $userAgent = $request->getHeaderLine('User-Agent');

        return [
            DatabaseSessionManager::ATTR_IP => $request->getAttribute('client_ip')
                ?? $request->getServerParams()['REMOTE_ADDR']
                ?? '',
            DatabaseSessionManager::ATTR_USER_AGENT => $userAgent,
            ...$this->deviceDetector->detect($userAgent),
        ];
    }
}
