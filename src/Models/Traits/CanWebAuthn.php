<?php

namespace LuiYongSheng\WebAuthn\Models\Traits;

use LuiYongSheng\WebAuthn\Models\WebAuthnCredential;

trait CanWebAuthn
{
    public function webauthnCredentials()
    {
        return $this->hasMany(WebAuthnCredential::class);
    }
}
