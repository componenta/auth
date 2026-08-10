<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

/** Enqueues OTP delivery without account lookup or sender I/O. */
final readonly class OtpRequester
{
    public function __construct(private OtpRequestQueueInterface $queue) {}

    public function request(string $identity, ?string $destination = null): void
    {
        $this->queue->enqueue(new OtpRequest($identity, $destination));
    }
}
