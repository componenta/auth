<?php

declare(strict_types=1);

namespace Componenta\Auth\Http\Strategy\Otp;

/** Queue message for the built-in identity-as-destination OTP flow. */
final readonly class OtpRequest
{
    public function __construct(
        public string $identity,
    ) {
        self::assertAddress($this->identity, 'OTP identity');
    }

    private static function assertAddress(string $value, string $label): void
    {
        if (
            $value === ''
            || strlen($value) > 320
            || trim($value) !== $value
            || preg_match('/[\x00-\x1F\x7F]/', $value) === 1
        ) {
            throw new \InvalidArgumentException($label . ' is invalid.');
        }
    }
}
