<?php

/**
 * Standalone function to verify an OpenID url for OpenID 2.0 providers.
 * The return_to url should be the location of this file.
 * The returned info I think is enough to parse sreg data out of
 * but this doesn't do it for you. Try using parse_url().
 */

/*
# Example usage:
if($user = openid_verify()) {
    print 'You have authenticated!';
} else {
    print '<form method="post" action="" class="openid">
        <input type="url" name="openid_verify">
        <input type="submit" value="Log In [OpenID]">
        </form>';
}
# */

function openid_verify($return_to = null, array $params = []) {
    if (!$return_to) {
        $return_to = 'http://'.getenv('HTTP_HOST').(getenv('REQUEST_URI') ?: '/');
    }

    if (isset($_POST['openid_verify'])) {
        $url = $_POST['openid_verify'];
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            throw new \InvalidArgumentException("Invalid OpenID URL.");
        }

        $need = [
            'openid.mode' => 'checkid_setup',
            'openid.ns' => 'http://specs.openid.net/auth/2.0',
            'openid.claimed_id' => 'http://specs.openid.net/auth/2.0/identifier_select',
            'openid.identity' => 'http://specs.openid.net/auth/2.0/identifier_select',
            'openid.return_to' => $return_to,
            'openid.realm' => $return_to,
        ];

        $meta = get_meta_tags($url);
        if (isset($meta['x-xrds-location'])) {
            $url = $meta['x-xrds-location'];
        }

        # For some reason I had to have a trailing slash for it to work.
        # So, add it to any URLs not containing "?", ";", or "&"...
        $url = (preg_match('/[?;&]/', $url) > 0)
            ? $url
            : trim($url, '/') .'/';

        $c = stream_context_create(['http' => [
            'method' => 'GET',
            'headers' => 'Accept: application/xrds+xml',
        ]]);

        $res = file_get_contents($url, null, $c);
        libxml_use_internal_errors(true);
        $xrds = simplexml_load_string($res);
        if (isset($xrds->XRD->Service->URI)) {
            $next = $xrds->XRD->Service->URI;
        }

        $params = array_merge($params, $need);
        $qs = parse_url($next, PHP_URL_QUERY);
        $next .= isset($qs) ? '&' : '?';
        $next .= http_build_query($params, '', '&');
        # Proceed to the next step - auth with endpoint extracted from XRDS data.
        header('Location: '.$next);
        exit(0);
    } elseif (isset($_GET['openid_mode'], $_GET['openid_op_endpoint']) && $_GET['openid_mode'] == 'id_res') {
        $url = $_GET['openid_op_endpoint'];
        $query = str_replace(
            'openid.mode=id_res',
            'openid.mode=check_authentication',
            getenv('QUERY_STRING')
        );

        $c = stream_context_create(['http' => [
            'method' => 'POST',
            'content' => $query,
            'header' => 'Content-Type: application/x-www-form-urlencoded',
        ]]);

        $res = file_get_contents($url, null, $c);

        return 0 === stripos(trim($res), 'is_valid:true');
    }
}

