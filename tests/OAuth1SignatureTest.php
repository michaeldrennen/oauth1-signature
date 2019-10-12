<?php

namespace MichaelDrennen\OAuth1Signature\Tests;


use MichaelDrennen\OAuth1Signature\OAuth1Signature;
use PHPUnit\Framework\TestCase;


class OAuth1SignatureTest extends TestCase {


    /**
     * @test
     */
    public function oauth1SignatureShouldReturnSignature() {
        $key           = 'somekey';
        $requestMethod = 'GET';
        $requestURL    = 'http://github.com/foobar';


        $headers     = [
            'oauth_consumer_key'     => "0685bd9184jfhq22",
            'oauth_token'            => "ad180jjd733klru7",
            'oauth_signature_method' => "HMAC-SHA1",
            'oauth_signature'        => "wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",
            'oauth_timestamp'        => "137131200",
            'oauth_nonce'            => "4572616e48616d6d65724c61686176",
            'oauth_version'          => "1.0",
        ];
        $postParams  = [
            'aParam' => 'foo',
        ];
        $queryParams = [
            'aParam' => 'bar',
        ];
        $signature   = OAuth1Signature::signature( $key, $requestMethod, $requestURL, $headers, $postParams, $queryParams );

        var_dump( $signature );
    }


}