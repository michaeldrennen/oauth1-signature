<?php

namespace MichaelDrennen\OAuth1Signature;

/**
 * @see https://oauth.net/core/1.0a/#signing_process
 * Class OAuth1Signature
 * @package MichaelDrennen\OAuth1Signature
 */
class OAuth1Signature {


    /**
     * @see https://oauth.net/core/1.0a/#RFC3986
     * @param string $key The secret key used for signing.
     * @param string $httpRequestMethod GET POST or HEAD in uppercase.
     * @param string $requestURL BAD: HTTP://Example.com:80/resource?id=123 GOOD: http://example.com/resource
     * @param array $headers @see https://oauth.net/core/1.0a/#auth_header_authorization
     * @param array $postParams
     * @param array $queryParams
     * @return string
     */
    public static function signature( string $key, string $httpRequestMethod, string $requestURL, array $headers = [], array $postParams = [], array $queryParams = [] ): string {

        $encodedHeaders     = self::encodeParameters( $headers );
        $encodedPostParams  = self::encodeParameters( $postParams );
        $encodedQueryParams = self::encodeParameters( $queryParams );

        $normalizedRequestParameters = self::normalizeRequestParameters( $encodedHeaders, $encodedPostParams, $encodedQueryParams );


        $signatureBaseStringParts = [
            $httpRequestMethod,
            $requestURL,
            $normalizedRequestParameters,
        ];

        $signatureBaseString = implode( '&', $signatureBaseStringParts );

        $signatureString = hash_hmac( "sha1", $signatureBaseString, $key, TRUE );

        $base64EncodedSignatureString = base64_encode($signatureString);


        return $base64EncodedSignatureString;

    }


    /**
     * @see https://oauth.net/core/1.0a/#encoding_parameters
     * @param array $params
     * @return array
     */
    protected static function encodeParameters( array $params ): array {
        $encodedParams = [];
        foreach ( $params as $name => $value ):
            $encodedParams[ $name ] = urlencode( $value );
        endforeach;
        return $encodedParams;
    }


    /**
     * @param array $encodedHeaders
     * @param array $encodedPostParams
     * @param array $encodedQueryParams
     * @return string A url encoded (%xx) string of all the request parameters from headers, GET, and POST.
     */
    protected static function normalizeRequestParameters( array $encodedHeaders = [], array $encodedPostParams = [], array $encodedQueryParams = [] ): string {
        $encodedPairs = [];

        self::addEncodedParamsToEncodedPairs( $encodedPairs, $encodedHeaders );
        self::addEncodedParamsToEncodedPairs( $encodedPairs, $encodedPostParams );
        self::addEncodedParamsToEncodedPairs( $encodedPairs, $encodedQueryParams );

        ksort( $encodedPairs );

        foreach ( $encodedPairs as $name => $value ):
            if ( is_array( $value ) ):
                sort( $encodedPairs[ $name ] );
            endif;
        endforeach;

        $normalizedPairs = [];

        foreach ( $encodedPairs as $name => $value ):
            if ( is_array( $value ) ):
                foreach ( $value as $i => $someValue ):
                    $normalizedPairs[] = $name . '=' . $someValue;
                endforeach;
            else:
                $normalizedPairs[] = $name . '=' . $value;
            endif;
        endforeach;


        return urlencode( implode( '&', $normalizedPairs ) );
    }

    /**
     * This little method is required to help me deal with a user submitting multiple request parameters with the same name.
     * @gotcha This is really only useful if the user supplies a parameter with the same name but in multiple
     * places like the header, post params, and/or query params.
     * @todo I guess I should code in the ability for a user to submit the same param multiple times in GET/POST/HEADER, but... I don't need that now.
     * @param array $encodedPairs
     * @param array $encodedParams
     */
    protected static function addEncodedParamsToEncodedPairs( &$encodedPairs = [], $encodedParams = [] ): void {
        foreach ( $encodedParams as $name => $value ):
            if ( isset( $encodedPairs[ $name ] ) && is_array( $encodedPairs[ $name ] ) ):
                $encodedPairs[ $name ][] = $value;


            // If we have a duplicate request parameter name, then create an array of values for that name.
            elseif
            ( isset( $encodedPairs[ $name ] ) && is_scalar( $encodedPairs[ $name ] ) ):
                $firstValueForName       = $encodedPairs[ $name ];
                $encodedPairs[ $name ]   = [];
                $encodedPairs[ $name ][] = $firstValueForName;
                $encodedPairs[ $name ][] = $value;
            else:
                $encodedPairs[ $name ] = $value;
            endif;
        endforeach;
    }


}