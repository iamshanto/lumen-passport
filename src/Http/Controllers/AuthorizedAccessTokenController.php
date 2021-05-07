<?php

namespace Lumen\Passport\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Lumen\Passport\RefreshTokenRepository;
use Lumen\Passport\TokenRepository;

class AuthorizedAccessTokenController
{
    /**
     * The token repository implementation.
     *
     * @var \Lumen\Passport\TokenRepository
     */
    protected $tokenRepository;

    /**
     * The refresh token repository implementation.
     *
     * @var \Lumen\Passport\RefreshTokenRepository
     */
    protected $refreshTokenRepository;

    /**
     * Create a new controller instance.
     *
     * @param  \Lumen\Passport\TokenRepository  $tokenRepository
     * @param  \Lumen\Passport\RefreshTokenRepository  $refreshTokenRepository
     * @return void
     */
    public function __construct(TokenRepository $tokenRepository, RefreshTokenRepository $refreshTokenRepository)
    {
        $this->tokenRepository = $tokenRepository;
        $this->refreshTokenRepository = $refreshTokenRepository;
    }

    /**
     * Get all of the authorized tokens for the authenticated user.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Database\Eloquent\Collection
     */
    public function forUser(Request $request)
    {
        $tokens = $this->tokenRepository->forUser($request->user()->getAuthIdentifier());

        return $tokens->load('client')->filter(function ($token) {
            return ! $token->client->firstParty() && ! $token->revoked;
        })->values();
    }

    /**
     * Delete the given token.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $tokenId
     * @return \Illuminate\Http\Response
     */
    public function destroy(Request $request, $tokenId)
    {
        $token = $this->tokenRepository->findForUser(
            $tokenId, $request->user()->getAuthIdentifier()
        );

        if (is_null($token)) {
            return new Response('', 404);
        }

        $token->revoke();

        $this->refreshTokenRepository->revokeRefreshTokensByAccessTokenId($tokenId);

        return new Response('', Response::HTTP_NO_CONTENT);
    }
}
