<?php

namespace LuiYongSheng\WebAuthn\Http\Controllers;

use Cose\Algorithms;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Validation\UnauthorizedException;
use InvalidArgumentException;
use LuiYongSheng\WebAuthn\WebAuthnServiceProvider;
use Psr\Http\Message\ServerRequestInterface as CredentialRequest;
use Webauthn\AuthenticatorAssertionResponse as LoginResponse;
use Webauthn\AuthenticatorAssertionResponseValidator as LoginValidator;
use Webauthn\AuthenticatorAttestationResponse as RegistrationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator as RegistrationValidator;
use Webauthn\AuthenticatorSelectionCriteria as Authenticator;
use Webauthn\PublicKeyCredentialCreationOptions as CreationRequest;
use Webauthn\PublicKeyCredentialDescriptor as Credential;
use Webauthn\PublicKeyCredentialLoader as CredentialLoader;
use Webauthn\PublicKeyCredentialParameters as CredentialParameter;
use Webauthn\PublicKeyCredentialRequestOptions as LoginRequest;
use Webauthn\PublicKeyCredentialRpEntity as RelyingParty;
use Webauthn\PublicKeyCredentialUserEntity as UserEntity;

class WebAuthnController
{
    public function createDetails(Request $request)
    {
        return tap(CreationRequest::create(
            new RelyingParty(config('app.name'), $request->getHttpHost()),
            new UserEntity(
                $request->user()->email,
                $request->user()->id,
                $request->user()->name,
            ),
            random_bytes(16),
            [
                new CredentialParameter(Credential::CREDENTIAL_TYPE_PUBLIC_KEY, Algorithms::COSE_ALGORITHM_ES256),
                new CredentialParameter(Credential::CREDENTIAL_TYPE_PUBLIC_KEY, Algorithms::COSE_ALGORITHM_RS256),
            ],
        )->setAuthenticatorSelection(new Authenticator('platform'))->excludeCredentials($request->user()->webauthnCredentials->map(function ($credential) {
            return new Credential(Credential::CREDENTIAL_TYPE_PUBLIC_KEY, $credential['credId'], ['internal']);
        })->toArray()), fn ($creationOptions) => Cache::put($this->getCacheKey(), $creationOptions->jsonSerialize(), now()->addMinutes(5)))->jsonSerialize();
    }

    public function create(Request $request, CredentialLoader $credentialLoader, RegistrationValidator $registrationValidator, CredentialRequest $credentialRequest)
    {
        $credentials     = $credentialLoader->loadArray($request->all())->getResponse();
        $creationOptions = CreationRequest::createFromArray(Cache::pull($this->getCacheKey()));

        if (! $creationOptions || ! $credentials instanceof RegistrationResponse) {
            throw new UnauthorizedException('Webauthn: Failed validating request', 422);
        }

        try {
            $response = $registrationValidator->check($credentials, $creationOptions, $credentialRequest, [$creationOptions->getRp()->getId()]);
        } catch (InvalidArgumentException $e) {
            throw new UnauthorizedException('Webauthn: Failed validating request', 422, $e);
        }

        $request->user()->webauthnCredentials()->create([
            'credId' => $credId = $response->getPublicKeyCredentialId(),
            'key'    => $response->getCredentialPublicKey(),
        ]);

        cookie()->queue(WebAuthnServiceProvider::WEBAUTHN_COOKIE, $credId, 1 * Carbon::DAYS_PER_YEAR * Carbon::HOURS_PER_DAY * Carbon::MINUTES_PER_HOUR);

        return response()->noContent();
    }

    public function loginDetails(Request $request)
    {
        return tap(
            LoginRequest::create(random_bytes(16))
            ->setRpId($request->getHttpHost())
            ->allowCredential(new Credential(Credential::CREDENTIAL_TYPE_PUBLIC_KEY, $request->cookie(WebAuthnServiceProvider::WEBAUTHN_COOKIE), ['internal'])),
            fn ($requestOptions) => Cache::put($this->getCacheKey(), $requestOptions->jsonSerialize(), now()->addMinutes(5))
        )->jsonSerialize();
    }

    public function login(Request $request, CredentialLoader $credentialLoader, LoginValidator $loginValidator, CredentialRequest $credentialRequest)
    {
        $credentials    = $credentialLoader->loadArray($request->all())->getResponse();
        $requestOptions = LoginRequest::createFromArray(Cache::pull($this->getCacheKey()));

        if (! $requestOptions || ! $credentials instanceof LoginResponse) {
            throw new UnauthorizedException('Webauthn: Failed validating request', 422);
        }

        try {
            $response = $loginValidator->check($request->cookie(WebAuthnServiceProvider::WEBAUTHN_COOKIE), $credentials, $requestOptions, $credentialRequest, null, [$requestOptions->getRpId()]);
        } catch (InvalidArgumentException $e) {
            throw new UnauthorizedException('Webauthn: Failed validating request', 422, $e);
        }

        Auth::loginUsingId(intval($response->getUserHandle()));

        return response()->noContent();
    }

    protected function getCacheKey()
    {
        return 'webauthn-request-'.sha1(request()->getHttpHost().session()->getId());
    }
}
