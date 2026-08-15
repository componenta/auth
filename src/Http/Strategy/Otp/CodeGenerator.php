<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

/** Generates a uniformly distributed numeric code without integer overflow. */
final readonly class CodeGenerator
{
    public function __construct(
        private OtpConfig $config,
    ) {}

    /** @throws \Random\RandomException */
    public function generate(): string
    {
        $code = '';

        for ($position = 0; $position < $this->config->length; ++$position) {
            $code .= (string) random_int(0, 9);
        }

        return $code;
    }
}
