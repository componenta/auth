<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

final readonly class OtpRequest
{
    public function __construct(
        public string $identity,
        public ?string $destination = null,
    ) {}
}
