<?php

namespace App\Http\Controllers;

use App\Http\Requests\VerifyRequest;
use App\Http\Services\AuthService;
use Elliptic\EC;
use Illuminate\Http\JsonResponse;
use kornrunner\Keccak;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\Validation\UnauthorizedException;

class Web3Controller extends Controller
{
    public function message()
    {
        $nonce = Str::random();
        $message = "Sign this message to confirm you own this wallet address. This action will not cost any gas fees.\n\nNonce: " . $nonce;


        return response()->json(['message' => $message]);
    }

    public function verify(VerifyRequest $request)
    {
        $data = $request->validated();

        $result = (new AuthService())->verifySignature($data['message'], $data['signature'], $data['address']);

        if (!$result)
            return response(['message' => 'Wrong Credentials'], JsonResponse::HTTP_UNAUTHORIZED);

        return ($result ? 'OK' : 'ERROR');
    }
}
