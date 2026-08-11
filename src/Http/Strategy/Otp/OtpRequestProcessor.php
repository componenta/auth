<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

use Componenta\Auth\Token\SenderInterface;
use Componenta\Auth\Token\UserProviderInterface;
use Componenta\Clock\Clock;
use Psr\Clock\ClockInterface;

final readonly class OtpRequestProcessor
{
    public function __construct(
        private UserProviderInterface $provider,
        private CodeGenerator $generator,
        private CodeStoreInterface $store,
        private SenderInterface $sender,
        private OtpConfig $config,
        private ClockInterface $clock = new Clock(),
    ) {}

    public function process(OtpRequest $request): void
    {
        $identity = $this->provider->findByIdentity($request->identity);

        if ($identity === null) {
            return;
        }

        $code = $this->generator->generate();
        $destination = $request->destination ?? $request->identity;
        $this->store->store(new StoredCode(
            subjectId: $identity->uuid,
            code: $code,
            destination: $destination,
            expiresAt: $this->clock->now()->getTimestamp() + $this->config->ttl,
        ));
        $this->sender->send($destination, $code);
    }
}
