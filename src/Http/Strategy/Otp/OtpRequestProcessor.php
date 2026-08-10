<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

use Componenta\Auth\AuthSubject;
use Componenta\Auth\Token\SenderInterface;
use Componenta\Auth\Token\UserProviderInterface;
use Componenta\Clock\Clock;
use Psr\Clock\ClockInterface;

/** Worker-side OTP generation, persistence and delivery. */
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
        $user = $this->provider->findByIdentity($request->identity);
        if ($user === null) {
            return;
        }
        $code = $this->generator->generate();
        $destination = $request->destination ?? $request->identity;
        $expiresAt = $this->clock->now()->getTimestamp() + $this->config->ttl;
        $this->store->store(new StoredCode(
            userId: (string) AuthSubject::id($user),
            code: $code,
            destination: $destination,
            expiresAt: $expiresAt,
        ));
        $this->sender->send($destination, $code);
    }
}
