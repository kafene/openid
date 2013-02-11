<?php

/*
 * Standalone function to verify an OpenID url for OpenID 2.0 providers
 * The return_to url should be the location of this file.
 * The returned info I think is enough to parse sreg data out of
 * but this doesn't do it for you. Try using parse_url().
 * @todo this stopped working but I still get sreg info?
 * // echo kafene\OpenID();
*/

function OpenID($return_to = null, array $params = [])
{
    // This is a rather basic guess.
    if ( null == $return_to )
    {   $return_to = 'http://'
                   . getenv('SERVER_NAME')
                   . '/'
                   . getenv('SCRIPT_NAME')
        ;
    }
    if ( isset($_POST['OpenID_Start_Verification']) )
    {   $ch = curl_init( $_POST['OpenID_Start_Verification'] );
        curl_setopt_array
        ( $ch
          , [ \CURLOPT_RETURNTRANSFER => true
          , \CURLOPT_SSL_VERIFYHOST => false
          , \CURLOPT_SSL_VERIFYPEER => false
          , \CURLOPT_HTTPHEADER     => [ 'Accept: application/xrds+xml' ]
          ]
        );
        $res = curl_exec($ch);
        curl_close($ch);
        // Parse XRDS data
        $next = simplexml_load_string($res) -> XRD -> Service -> URI
        ;
        $id_select = 'http://specs.openid.net/auth/2.0/identifier_select';
        $need =
          [ 'openid.mode'       => 'checkid_setup'
          , 'openid.ns'         => 'http://specs.openid.net/auth/2.0'
          , 'openid.claimed_id' => $id_select
          , 'openid.identity'   => $id_select
          , 'openid.return_to'  => $return_to
          , 'openid.realm'      => $return_to
          ];
        $params = array_merge($params, $need);
        $qs    = parse_url($next, \PHP_URL_QUERY);
        $next .= ( $qs ? '&' : '?' ) . http_build_query($params);
        exit(
            header('Location: ' . $next)
        );
    } elseif
    ( isset
        ( $_GET['openid_mode']
        , $_GET['openid_op_endpoint']
        )
        && $_GET['openid_mode'] == 'id_res'
    )
    {   $ch = curl_init( $_GET['openid_op_endpoint'] );
        $next = str_replace
        ( 'openid.mode=id_res'
        , 'openid.mode=check_authentication'
        , $_SERVER['QUERY_STRING']
        );
        curl_setopt_array
        ( $ch
          , [ \CURLOPT_POST => true
            , \CURLOPT_RETURNTRANSFER => true
            , \CURLOPT_SSL_VERIFYHOST => false
            , \CURLOPT_SSL_VERIFYPEER => false
            , \CURLOPT_POSTFIELDS => array($next)
            ]
        );
        $res = curl_exec($ch);
        curl_close($ch);
        return
        [ 'response' => $res
        , 'get'      => $_GET
        , 'valid'    => stripos($res, 'is_valid:true') !== false
        ];
    } else
    {   return '<form method="post" action="" class="OpenIDVerificationForm">'
             . '<input type="url" name="OpenID_Start_Verification">'
             . '<input type="submit" value="Log In [OpenID]">'
             . '</form>';
    }
}
