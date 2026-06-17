<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

use Componenta\Auth\AuthSubject;
use Componenta\Auth\Exception\TransportException;
use Componenta\Auth\Token\SenderInterface;
use Componenta\Auth\Token\UserProviderInterface;
use Componenta\Clock\Clock;
use Psr\Clock\ClockInterface;

/**
 * Handles the request step of the OTP flow.
 *
 * Looks up the user by identity, generates a random code,
 * stores it, and sends it via the configured sender.
 *
 * This is NOT an authentication strategy - it does not return
 * an authenticated user. It is a standalone service used by
 * application-level controllers.
 *
 * To prevent user enumeration, the calling handler should
 * return a success response regardless of this method's return value.
 */
final readonly class OtpRequester
{
    public function __construct(
        private UserProviderInterface $provider,
        private CodeGenerator $generator,
        private CodeStoreInterface $store,
        private SenderInterface $sender,
        private OtpConfig $config,
        private ClockInterface $clock = new Clock(),
    ) {}

    /**
     * Generates an OTP code and sends it to the user.
     *
     * @param string $identity User identity (phone number, email)
     * @param string|null $destination Delivery address; defaults to identity
     * @return bool True if user exists and code was sent
     *
     * @throws TransportException On send failure
     */
    public function request(string $identity, ?string $destination = null): bool
    {
        $user = $this->provider->findByIdentity($identity);

        if ($user === null) {
            return false;
        }

        $code = $this->generator->generate();
        $dest = $destination ?? $identity;
        $expiresAt = $this->clock->now()->getTimestamp() + $this->config->ttl;

        $this->store->store(new StoredCode(
            userId: (string) AuthSubject::id($user),
            code: $code,
            destination: $dest,
            expiresAt: $expiresAt,
        ));

        $this->sender->send($dest, $code);

        return true;
    }
}
