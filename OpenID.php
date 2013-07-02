<?php

/**
 * Standalone function to verify an OpenID url for OpenID 2.0 providers
 * The return_to url should be the location of this file.
 * The returned info I think is enough to parse sreg data out of
 * but this doesn't do it for you. Try using parse_url().
 * @todo this stopped working but I still get sreg info?
 * # echo openid_verify();
*/
function openid_verify($return_to = null, array $params = []) {
    if(null == $return_to) {
        $return_to = 'http://'.getenv('HTTP_HOST').(getenv('REQUEST_URI') ?: '/');
    }
    if(isset($_POST['openid_verify'])) {
        $ch = curl_init($_POST['openid_verify']);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_HTTPHEADER => ['Accept: application/xrds+xml'],
        ]);
        $response = curl_exec($ch);
        curl_close($ch);
        $next = simplexml_load_string($response)->XRD->Service->URI;
        $id_select = 'http://specs.openid.net/auth/2.0/identifier_select';
        $need = [
            'openid.mode' => 'checkid_setup',
            'openid.ns' => 'http://specs.openid.net/auth/2.0',
            'openid.claimed_id' => $id_select,
            'openid.identity' => $id_select,
            'openid.return_to' => $return_to,
            'openid.realm' => $return_to
        ];
        $params = array_merge($need, $params);
        $q = parse_url($next, PHP_URL_QUERY) ? '&' : '?';
        $next .= $q.http_build_query($params);
        header('Location: '.$next);
        exit(0);
    } elseif(
        isset($_GET['openid_mode'], $_GET['openid_op_endpoint'])
        && $_GET['openid_mode'] == 'id_res'
    ) {
        $ch = curl_init($_GET['openid_op_endpoint']);
        $next = str_replace(
            'openid.mode=id_res',
            'openid.mode=check_authentication',
            getenv('QUERY_STRING')
        );
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_POSTFIELDS => [$next]
        ]);
        $response = curl_exec($ch);
        curl_close($ch);
        $valid = false !== stripos($response, 'is_valid:true');
        return compact('response', 'valid');
    } else {
        return '
            <form method="post" action="" class="openid">
            <input type="url" name="openid_verify">
            <input type="submit" value="Log In [OpenID]">
            </form>
        ';
    }
}
