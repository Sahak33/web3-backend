<?php

namespace App\Http\Controllers;

use App\Http\Requests\VerifyRequest;
use App\Http\Services\AuthService;
use Elliptic\EC;
use Illuminate\Http\JsonResponse;
use kornrunner\Keccak;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;
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

        $authService = new AuthService();
        $result = $authService->verifySignature($data['message'], $data['signature'], $data['address']);

        if (!$result)
            return response(['message' => 'Wrong Credentials'], JsonResponse::HTTP_UNAUTHORIZED);


        $user = $authService->userExist($data['address']);
        if (!$user) {
            $user = $authService->createUser($data['address']);
        }
        $token = $user->createToken('MyApp')->plainTextToken;
        return response()->json(['token' => $token]);
    }


    public function getWalletNfts(Request $request)
    {


        $response = Http::withHeaders([
            'Accept' => 'application/json',
            'X-API-Key' => env('MORALIS_API_KEY'),
        ])->get('https://deep-index.moralis.io/api/v2/' . Auth::user()->address . '/nft', [
            'chain' => 'eth',
            'format' => 'decimal',
            'media_items' => false,
        ]);

        return $response->json();
    }
}
