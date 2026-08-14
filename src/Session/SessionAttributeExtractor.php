<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

use Psr\Http\Message\ServerRequestInterface;

final readonly class SessionAttributeExtractor implements SessionAttributeExtractorInterface
{
    private const int MAX_USER_AGENT_LENGTH = 1024;

    public function __construct(
        private DeviceDetector $deviceDetector = new DeviceDetector(),
    ) {}

    #[\Override]
    public function extract(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): array {
        $userAgent = substr(
            $request->getHeaderLine('User-Agent'),
            0,
            self::MAX_USER_AGENT_LENGTH,
        );
        $clientIp = $request->getAttribute('client_ip')
            ?? $request->getServerParams()['REMOTE_ADDR']
            ?? '';
        $validIp = is_string($clientIp)
            && strlen($clientIp) <= 45
            && ($clientIp === '' || filter_var(
                $clientIp,
                FILTER_VALIDATE_IP,
            ) !== false);
        $ip = $validIp ? $clientIp : '';

        return [
            DatabaseSessionManager::ATTR_IP => $ip,
            DatabaseSessionManager::ATTR_USER_AGENT => $userAgent,
            ...$this->deviceDetector->detect($userAgent),
        ];
    }
}
