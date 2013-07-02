<?php

/**
 * Standalone function to verify an OpenID url for OpenID 2.0 providers
 * The return_to url should be the location of this file.
 * The returned info I think is enough to parse sreg data out of
 * but this doesn't do it for you. Try using parse_url().
 * @todo this stopped working but I still get sreg info?
 * # echo openid_verify();
*/
echo openid_verify();
function openid_verify($return_to = null, array $params = []) {
    if(!$return_to) {
        $return_to = 'http://'.getenv('HTTP_HOST').(getenv('REQUEST_URI') ?: '/');
    }
    if(isset($_POST['openid_verify'])) {
        $url = $_POST['openid_verify'];
        $need = [
            'openid.mode' => 'checkid_setup',
            'openid.ns' => 'http://specs.openid.net/auth/2.0',
            'openid.claimed_id' => 'http://specs.openid.net/auth/2.0/identifier_select',
            'openid.identity' => 'http://specs.openid.net/auth/2.0/identifier_select',
            'openid.return_to' => $return_to,
            'openid.realm' => $return_to,
        ];
        $meta = get_meta_tags($url);
        if(isset($meta['x-xrds-location'])) {
            $url = $meta['x-xrds-location'];
        }
        $c = stream_context_create(['http' => [
            'method' => 'GET',
            'headers' => 'Accept: application/xrds+xml',
        ]]);
        $response = file_get_contents($url, null, $c);
        libxml_use_internal_errors(true);
        $xrds = simplexml_load_string($response);
        if(isset($xrds->XRD->Service->URI)) {
            $next = $xrds->XRD->Service->URI;
        }
        $params = array_merge($params, $need);
        $qs = parse_url($next, PHP_URL_QUERY);
        $next .= isset($qs) ? '&' : '?';
        $next .= http_build_query($params);
        header('Location: '.$next);
        exit(0);
    } elseif(isset($_GET['openid_mode'], $_GET['openid_op_endpoint']) && $_GET['openid_mode'] == 'id_res') {
        $url = $_GET['openid_op_endpoint'];
        $data = str_replace(
            'openid.mode=id_res',
            'openid.mode=check_authentication',
            getenv('QUERY_STRING')
        );
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_POSTFIELDS => $data
        ]);
        $response = curl_exec($ch);
        curl_close($ch);
        return 0 === stripos(trim($response), 'is_valid:true');
    } else {
        return '
            <form method="post" action="" class="openid">
            <input type="url" name="openid_verify">
            <input type="submit" value="Log In [OpenID]">
            </form>
        ';
    }
}
