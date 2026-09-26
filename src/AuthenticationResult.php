<?php

declare(strict_types=1);

namespace Componenta\Auth;

use Componenta\Identity\IdentityInterface;

final readonly class AuthenticationResult implements \JsonSerializable
{
    public ?AuthenticationEvidence $evidence;

    public function __construct(
        #[\SensitiveParameter]
        public IdentityInterface|DeniedReasonInterface $subject,
        #[\SensitiveParameter]
        public ?object $transportPayload = null,
        #[\SensitiveParameter]
        public ?object $state = null,
        public bool $continueOnFailure = false,
        ?AuthenticationEvidence $evidence = null,
    ) {
        if ($this->subject instanceof DeniedReasonInterface) {
            if (
                $this->transportPayload !== null
                || $this->state !== null
                || $evidence !== null
            ) {
                throw new \InvalidArgumentException(
                    'A denied authentication result cannot contain evidence, credential mutations or authentication state.',
                );
            }

            $this->evidence = null;

            return;
        }

        if ($this->continueOnFailure) {
            throw new \InvalidArgumentException(
                'A successful authentication result cannot continue the strategy chain.',
            );
        }

        $this->evidence = $evidence ?? AuthenticationEvidence::unknown();
    }

    /**
     * @return array{
     *     subjectType: class-string,
     *     subjectId: string|null,
     *     deniedCode: string|null,
     *     transportPayloadType: class-string|null,
     *     stateType: class-string|null,
     *     continueOnFailure: bool,
     *     evidence: array{methods: non-empty-list<string>, capabilities: list<string>}|null
     * }
     */
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
            'stateType' => $this->state === null ? null : $this->state::class,
            'continueOnFailure' => $this->continueOnFailure,
            'evidence' => $this->evidence?->__debugInfo(),
        ];
    }

    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}
