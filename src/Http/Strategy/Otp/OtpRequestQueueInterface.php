<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

/**
 * Queue for the uniform OTP request path.
 *
 * Production adapters should be durable and non-inline when account-existence
 * timing matters: provider lookup, challenge persistence and delivery must not
 * become part of the public request latency.
 */
interface OtpRequestQueueInterface
{
    public function enqueue(OtpRequest $request): void;
}
