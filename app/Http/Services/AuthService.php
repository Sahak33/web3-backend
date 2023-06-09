<?php

namespace App\Http\Services;

use App\Models\User;
use Elliptic\EC;
use Illuminate\Support\Facades\Http;
use kornrunner\Keccak;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Auth;
class AuthService
{

    public function verifySignature(string $message, string $signature, string $address): bool
    {
        $hash = Keccak::hash(sprintf("\x19Ethereum Signed Message:\n%s%s", strlen($message), $message), 256);
        $sign = [
            'r' => substr($signature, 2, 64),
            's' => substr($signature, 66, 64),
        ];

        $recid = ord(hex2bin(substr($signature, 130, 2))) - 27;

        if ($recid != ($recid & 1)) {
            return false;
        }

        $pubkey = (new EC('secp256k1'))->recoverPubKey($hash, $sign, $recid);
        $derived_address = '0x' . substr(Keccak::hash(substr(hex2bin($pubkey->encode('hex')), 1), 256), 24);

        return (Str::lower($address) === $derived_address);
    }

    public function userExist(string $address)
    {
        return User::where('address', $address)->first();
    }

    public function createUser(string $address)
    {
        return User::create(['address' => $address]);
    }


    public function getUserNfts() {
        return Http::withHeaders([
            'Accept' => 'application/json',
            'X-API-Key' => env('MORALIS_API_KEY'),
        ])->get('https://deep-index.moralis.io/api/v2/' . Auth::user()->address . '/nft', [
            'chain' => 'eth',
            'format' => 'decimal',
            'media_items' => false,
        ]);
    }
}
