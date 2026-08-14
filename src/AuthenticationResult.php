<?php

declare(strict_types=1);

namespace Componenta\Auth;

use Componenta\Auth\Session\SessionInterface;
use Componenta\Identity\IdentityInterface;

final readonly class AuthenticationResult implements \JsonSerializable
{
    public function __construct(
        #[\SensitiveParameter]
        public IdentityInterface|DeniedReasonInterface $subject,
        #[\SensitiveParameter]
        public ?object $transportPayload = null,
        #[\SensitiveParameter]
        public ?SessionInterface $session = null,
        public bool $continueOnFailure = false,
    ) {
        if ($this->subject instanceof DeniedReasonInterface) {
            if ($this->transportPayload !== null || $this->session !== null) {
                throw new \InvalidArgumentException(
                    'A denied authentication result cannot contain credential mutations or a session.',
                );
            }

            return;
        }

        if ($this->continueOnFailure) {
            throw new \InvalidArgumentException(
                'A successful authentication result cannot continue the strategy chain.',
            );
        }

        if (
            $this->session !== null
            && !$this->session->subjectId->equals($this->subject->uuid)
        ) {
            throw new \InvalidArgumentException(
                'The authenticated session must belong to the returned identity.',
            );
        }
    }

    /** @return array<string, bool|string|null> */
    public function __debugInfo(): array
    {
        return [
            'subjectType' => $this->subject::class,
            'subjectId' => $this->subject instanceof IdentityInterface
                ? $this->subject->uuid->toString()
                : null,
            'deniedCode' => $this->subject instanceof DeniedReasonInterface
                ? $this->subject->code
                : null,
            'transportPayloadType' => $this->transportPayload === null
                ? null
                : $this->transportPayload::class,
            'hasSession' => $this->session !== null,
            'continueOnFailure' => $this->continueOnFailure,
        ];
    }

    /** @return array<string, bool|string|null> */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}
