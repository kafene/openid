<?php

# ! ATTN ! Do not use this, it hasn't been completed.
# Original source - https://gitorious.org/lightopenid

/*
(new LightOpenIdProvider([
    'username' => 'jdoe',
    'password' => 'hunter2',
    'user_info' => [
        'fullname' => 'John Doe',
        'nickname' => 'John',
        'email' => 'jdoe@example.com',
        'dob' => '1969-12-31',
        'gender' => 'M',
        'postcode' => '10001',
        'country' => 'US',
        'language' => 'en-US',
        'timezone' => 'America/New_York',
    ],
]))->server();
*/

/**
 * Using this class, you can easily set up an OpenID Provider.
 * It's independent of LightOpenID class.
 * It requires either GMP or BCMath for session encryption.
 * Also, it requires PHP >= 5.4
 *
 * This is an alpha version, using it in production code is not recommended,
 * until you are *sure* that it works and is secure.
 *
 * Please send me messages about your testing results
 * (even if successful, so I know that it has been tested).
 * Also, if you think there's a way to make it easier to use,
 * tell me -- it's an alpha for a reason.
 * Same thing applies to bugs in code, suggestions,
 * and everything else you'd like to say about the library.
 *
 * There's no usage documentation here, see the examples.
 *
 * @author Mewp
 * @copyright Copyright (c) 2010, Mewp
 * @license http://www.opensource.org/licenses/mit-license.php MIT
 * @link http://gitorious.org/lightopenid
 */
class LightOpenIdProvider
{

    protected $selectId = true; # Server or Sign-on mode?
    protected $assoc;

    /**
     * User configuration array
     * The default value is an example/template.
     * You must provide your own config array when
     * instantiating this class. You only have to
     * include one of each type (sreg or ax) data
     * in the config.
     * @see http://openid.net/specs/openid-attribute-properties-list-1_0-01.html
     * @see ftp://ftp.isi.edu/in-notes/rfc4646.txt (Tags for Identifying Languages)
     *
     * @var array
     */
    protected $config = [
        'username' => 'jdoe',
        'password' => 'hunter2',
        'user_info' => [
            'fullname' => 'John Doe',
            'nickname' => 'John',
            'email' => 'jdoe@example.com',
            'dob' => '1969-12-31', # YYYY-MM-DD
            'gender' => 'M', # M/F
            'postcode' => '10001',
            'country' => 'US', # ISO 3166
            'language' => 'en-US', # ISO 639
            'timezone' => 'America/New_York', # tzdata
        ],
        'params' => [],
        'env' => [],
        'server_location' => '',
        'xrds_location' => '',
        'math_functions' => [],
        'assoc_lifetime' => 600,
    ];

    /**
     * Constructor. Sets some stuff up.
     *
     * @param array $config User configuration
     */
    public function __construct(array $config)
    {
        $this->config = $config;
        $this->assoc = [];

        # If we use select_id, we must disable it for identity pages,
        # so that an RP can discover it and get proper data (i.e. without select_id)
        if ($this->getParam('id')) {
            $this->selectId = false;
        }
    }

    /**
     * Environment data, getenv(), $_ENV, $_SERVER, etc.
     * First place looked in is $this->config['env'] so it can be overridden.
     *
     * @param mixed $key The key to look up
     * @param mixed $default Default return value
     *
     * @return string The found env. variable or default
     */
    protected function getEnv($key, $default = null)
    {
        $key_a = $key;
        $key_b = str_replace('_', '.', $key);

        if (isset($this->config['env'], $this->config['env'][$key_a]))
        {
            return $this->config['env'][$key_a];
        }

        elseif (isset($this->config['env'], $this->config['env'][$key_b]))
        {
            return $this->config['env'][$key_b];
        }

        elseif ($result_a = getenv($key_a))
        {
            return $result_a;
        }

        elseif ($result_b = getenv($key_b))
        {
            return $result_b;
        }

        elseif (isset($_ENV, $_ENV[$key_a]))
        {
            return $_ENV[$key_a];
        }

        elseif (isset($_ENV, $_ENV[$key_b]))
        {
            return $_ENV[$key_b];
        }

        elseif (isset($_SERVER, $_SERVER[$key_a]))
        {
            return $_SERVER[$key_a];
        }

        elseif (isset($_SERVER, $_SERVER[$key_b]))
        {
            return $_SERVER[$key_b];
        }

        else
        {
            return $default;
        }
    }

    /**
     * "Dirty"/user data, $_POST, $_GET, etc.
     * First place looked in is $this->config['params'] so it can be overridden.
     *
     * @param string $key The key to look up
     * @param mixed $default Default return value.
     *
     * @return mixed The found param variable or default
     */
    protected function getParam($key, $default = null)
    {
        $key_a = $key;
        $key_b = str_replace('_', '.', $key);

        if (isset($this->config['params'], $this->config['params'][$key_a]))
        {
            return $this->config['params'][$key_b];
        }

        elseif (isset($this->config['params'], $this->config['params'][$key_b]))
        {
            return $this->config['params'][$key_b];
        }

        elseif (isset($_POST, $_POST[$key_a]))
        {
            return $_POST[$key_a];
        }

        elseif (isset($_POST, $_POST[$key_b]))
        {
            return $_POST[$key_b];
        }

        elseif (isset($_GET, $_GET[$key_a]))
        {
            return $_GET[$key_a];
        }

        elseif (isset($_GET, $_GET[$key_b]))
        {
            return $_GET[$key_b];
        }

        elseif (isset($_REQUEST, $_REQUEST[$key_a]))
        {
            return $_REQUEST[$key_a];
        }

        elseif (isset($_REQUEST, $_REQUEST[$key_b]))
        {
            return $_REQUEST[$key_b];
        }

        else
        {
            return $default;
        }
    }

    /**
     * Set a parameter into the "dirty" params.
     *
     * @param string $key Key to set
     * @param mixed $value Value to set
     */
    protected function setParam($key, $value)
    {
        if (empty($this->config['params'])) {
            $this->config['params'] = [];
        }

        $this->config['params'][$key] = $value;
    }

    /**
     * Get all of the "dirty" param data that is set in config.
     *
     * @return array The data
     */
    protected function getParams()
    {
        if (empty($this->config['params'])) {
            $this->config['params'] = [];
        }

        return $this->config['params'];
    }

    /**
     * Set all of the "dirty" param data that is set in config.
     *
     * @param array $newParams The new param data.
     */
    protected function setParams(array $newParams)
    {
        $this->config['params'] = $newParams;
    }

    /**
     * Get the server location.
     * First place looked in is $this->config['server_location'] so
     * it can be overridden.
     * Must be in the form of a full url: http://host:port/path/to/script.php
     * The port part is optional, as is the path if this is the index file.
     *
     * @throws Exception If Host name can not be determined.
     *
     * @return string The server location URL.
     */
    protected function getServerLocation()
    {
        if (!empty($this->config['server_location'])) {
            return $this->config['server_location'];
        }

        $https = filter_var($this->getEnv('HTTPS'), FILTER_VALIDATE_BOOLEAN);
        $http = $https ? 'https://' : 'http://';
        $port = (int) $this->getEnv('SERVER_PORT');
        $port = (($https && $port === 443) || (!$https && $port === 80))
            ? ''
            : ':'.$port;
        $host = $this->getEnv('HTTP_HOST');

        if (!$host) {
            $host = $this->getEnv('SERVER_NAME');
        }

        if (!$host) {
            $host = $this->getEnv('SERVER_ADDR');
        }

        if (!$host) {
            static::raise('Failed to detect server host name.');
        }

        $path = $this->getEnv('REQUEST_URI', '/');
        $path = preg_replace('/\?.*$/', '', $path);
        $path = ltrim($path, '/');

        return $http.$host.$port.'/'.$path;
    }

    /**
     * Get the XRDS Location.
     * First place looked in is $this->config['xrds_location'],
     * so it can be overridden.
     * Should be like http://example.com/openid.php?xrds
     *
     * @return string XRDS Location.
     */
    protected function getXrdsLocation()
    {
        if (!empty($this->config['xrds_location'])) {
            return $this->config['xrds_location'];
        }

        $xrdsLocation = $this->getServerLocation();

        if (false !== strpos($location, '?')) {
            $xrdsLocation .= '&xrds';
        } else {
            $xrdsLocation .= '?xrds';
        }

        return $xrdsLocation;
    }

    /**
     * Returns Things defined in the OpenID spec.
     *
     * @return object OpenID Spec Stuff
     */
    protected function spec()
    {
        $spec = new \StdClass;
        $spec->ns = 'http://specs.openid.net/auth/2.0';
        $spec->defaultModulus =
            'ANz5OguIOXLsDhmYmsWizjEOHTdxfo2Vcbt2I3MYZuYe91ouJ4mLBX+YkcLiemOcPy'.
            'm2CBRYHNOyyjmG0mg3BVd9RcLn5S3IHHoXGHblzqdLFEi/368Ygo79JRnxTkXjgmY0'.
            'rxlJ5bU1zIKaSDuKdiI+XUkKJX8Fvf8W8vsixYOr';
        $spec->defaultGen = 'Ag==';

        return $spec;
    }

    /**
     * We will need to use bcmath or gmp.
     * Also hash() functions.
     * This returns an object containing methods to use.
     * Can be overridden from $this->config['math_functinos'],
     * but it is neither recommended nor supported.
     *
     * @throws \LightOpenIdException if Neither is available.
     *
     * @return object An object with methods add, mul, pow, mod, div, powmod
     */
    protected function &math()
    {
        static $math;

        if (!empty($this->config['math_functions'])) {
            return $this->config['math_functions'];
        }

        if (!function_exists('hash_algos')) {
            static::raise('Your PHP installation is missing the hash_algos function.');
        }

        if (!$math && function_exists('gmp_init'))
        {
            $math = new \StdClass;

            $math->mul = function ($a, $b) {
                return gmp_mul((string) $a, (string) $b);
            };
            $math->add = function ($a, $b) {
                return gmp_add((string) $a, (string) $b);
            };
            $math->pow = function ($a, $b) {
                return gmp_pow((string) $a, (string) $b);
            };
            $math->mod = function ($a, $b) {
                return gmp_mod((string) $a, (string) $b);
            };
            $math->div = function ($a, $b) {
                return gmp_div((string) $a, (string) $b);
            };
            $math->powmod = function ($a, $b, $c) {
                return gmp_powm((string) $a, (string) $b, (string) $c);
            };
        }
        elseif (!$math && function_exists('bcadd'))
        {
            $math = new \StdClass;

            $math->mul = function ($a, $b) {
                return bcmul((string) $a, (string) $b);
            };
            $math->add = function ($a, $b) {
                return bcadd((string) $a, (string) $b);
            };
            $math->pow = function ($a, $b) {
                return bcpow((string) $a, (string) $b);
            };
            $math->mod = function ($a, $b) {
                return bcmod((string) $a, (string) $b);
            };
            $math->div = function ($a, $b) {
                return bcdiv((string) $a, (string) $b);
            };
            $math->powmod = function ($a, $b) {
                return bcpowmod((string) $a, (string) $b, (string) $c);
            };
        }

        else
        {
            static::raise('Your PHP installation is missing one of GMP or BCMath.');
        }

        return $math;
    }

    /**
     * Get the configured username.
     *
     * @throws \LightOpenIdException If No username is Set
     *
     * @return String The configured username
     */
    protected function getUsername()
    {
        if (isset($this->config['username'])) {
            return $this->config['username'];
        }
 
        static::raise('No username specified in the configuration.');
    }

    /**
     * Get the configured password.
     * This is only required if `digest_a1` is not set.
     * If `digest_a1` is set then this won't be called.
     *
     * @throws \LightOpenIdException If No password is Set
     *
     * @return String The configured password
     */
    protected function getPassword()
    {
        if (isset($this->config['password'])) {
            return $this->config['password'];
        }

        static::raise('No password specified in the configuration.');
    }

    /**
     * Get the user's A1 value for HTTP Digest Auth
     * It is safer to set this instead of a password.
     * To calculate, use md5('USERNAME:REALM:PASSWORD')
     *
     * @return String The preconfigured A1 value, if any.
     */
    protected function getA1() {
        if (isset($this->config['digest_a1'])) {
            return $this->config['digest_a1'];
        }
    }

    /**
     * Get the configured assoc lifetime.
     *
     * @return The configured lifetime, or 600 as a default if none is set.
     */
    protected function getAssocLifetime()
    {
        if (isset($this->config['assoc_lifetime'])) {
            return (int) $this->config['assoc_lifetime'];
        } else {
            return 600;
        }
    }

    /**
     * Checks whether an user is authenticated.
     * The function should determine what fields it wants to send to the RP,
     * and put them in the $attributes array.
     *
     * @param String $realm Realm used for authentication.
     * @param Array $attributes
     *
     * @return String OP-local identifier of an authenticated user, or an empty value.
     */
    protected function checkId($realm, array &$attributes)
    {
        $default = ['nonce', 'nc', 'cnonce', 'qop', 'username', 'uri', 'response'];
        $digest = $this->getEnv('PHP_AUTH_DIGEST');

        if (
            !$digest ||
            !preg_match_all('/(\w+)="?([^",]+)"?/', $digest, $matches)
        ) {
            return false;
        }

        $data = array_combine($matches[1] + $default, $matches[2]);

        $a1 = $this->getA1()
            ?: md5(join(':', [
                $data['username'],
                $realm,
                $this->getPassword(),
            ]));

        $a2 = md5(join(':', [
            $this->getEnv('REQUEST_METHOD'),
            $data['uri'],
        ]));

        $valid = md5(join(':', [
            $a1,
            $data['nonce'],
            $data['nc'],
            $data['cnonce'],
            $data['qop'],
            $a2,
        ]));

        if (0 !== strcmp($data['response'], $valid)) {
            return false;
        }

        # Returning identity
        # It can be any url that leads here, or to any other place that hosts
        # an XRDS document pointing here.
        # @todo - can move ?id= somewhere configurable?
        # maybe $this->config['identity_url_format'] = sprintf(%s?id=%s)
        $identityUrl = $this->getServerLocation();

        if (false !== strpos($location, '?')) {
            $identityUrl .= '&id=';
        } else {
            $identityUrl .= '?id=';
        }

        $identityUrl .= $this->getUsername();

        return $identityUrl;
    }

    /**
     * Displays an user interface for inputting user's login and password.
     * Attributes are always AX field namespaces, with stripped host part.
     * For example, the $attributes array may be:
     * [
     *     'required' => ['namePerson/friendly', 'contact/email'],
     *     'optional' => ['pref/timezone', 'pref/language'],
     * ];
     *
     * @param String $identity
     *     Discovered identity string.
     *     May be used to extract login, unless using $this->select_id
     * @param String $realm Realm used for authentication.
     * @param String Association handle.
     *     Must be sent as openid.assoc_handle in $_GET
     *     or $_POST in subsequent requests.
     * @param Array User attributes requested by the RP.
     */
    protected function setup($identity, $realm, $assocHandle, array $attributes)
    {
        $realm = 'realm="'.$this->getParam('openid_realm').'"';
        $format = 'Digest ';
        $header = sprintf($format, $realm, uniqid('', true), md5($realm));

        header('HTTP/1.1 401 Unauthorized', true, 401);

        header(join('', [
            'WWW-Authenticate: Digest ',
            'realm="'.$realm.'",',
            'qop="auth",',
            'nonce="'.$this->assocHandle().'",',
            'opaque="'.md5($realm).'"',
        ]);

        exit;
    }

    /**
     * Returns the AX to SREG transformation map
     *
     * @link http://openid.net/specs/openid-attribute-exchange-1_0.html
     * @link http://openid.net/specs/openid-simple-registration-extension-1_0.html
     *
     * @return array Ax to SREG map.
     */
    protected function getAxToSregMap()
    {
        return [
            'namePerson/friendly' => 'nickname',
            'contact/email' => 'email',
            'namePerson' => 'fullname',
            'birthDate' => 'dob',
            'person/gender' => 'gender',
            'contact/postalCode/home' => 'postcode',
            'contact/country/home' => 'country',
            'pref/language' => 'language',
            'pref/timezone' => 'timezone',
        ];
    }

    /**
     * Stores an association.
     *
     * @param String $handle Association handle -- should be used as a key.
     * @param Array $assoc Association data.
     *
     * @return string The old Session ID, if any.
     */
    protected function setAssoc($handle, $assoc)
    {
        $oldSession = session_id();

        session_commit();
        session_id($assoc['handle']);
        session_start();

        $_SESSION['assoc'] = $assoc;

        session_commit();

        if ($oldSession) {
            session_id($oldSession);
            session_start();
        }

        return $oldSession;
    }

    /**
     * Retreives association data.
     *
     * @param String $handle Association handle.
     *
     * @return Array Association data.
     */
    protected function getAssoc($handle)
    {
        $oldSession = session_id();

        session_commit();
        session_id($handle);
        session_start();

        $assoc = null;

        if (!empty($_SESSION['assoc'])) {
            $assoc = $_SESSION['assoc'];
        }

        session_commit();

        if ($oldSession) {
            session_id($oldSession);
            session_start();
        }

        return $assoc;
    }

    /**
     * Deletes an association.
     *
     * @param String $handle Association handle.
     *
     * @return string The old Session ID, if any.
     */
    protected function delAssoc($handle)
    {

        $oldSession = session_id();

        session_commit();
        session_id($handle);
        session_start();
        session_destroy();

        if ($oldSession) {
            session_id($oldSession);
            session_start();
            return $oldSession;
        }
    }

    /**
     * Redirects the user to an url.
     *
     * @param String $location The url that the user will be redirected to.
     */
    protected function redirect($location)
    {
        header('Location: '.$location);

        exit;
    }

    /**
     * Generates a new association handle.
     *
     * @return string
     */
    protected function assocHandle()
    {
        return hash('sha256', uniqid('', true));
    }

    /**
     * Generates a random shared secret.
     *
     * @return string
     */
    protected function sharedSecret($hash)
    {
        $length = ('sha256' === $hash) ? 256 : 20;
        $secret = '';

        for ($i = 0; $i < $length; $i++) {
            $secret .= mt_rand(0,255);
        }

        return $secret;
    }

    /**
     * Generates a private key.
     *
     * @param int $length Length of the key.
     */
    protected function keyGen($length)
    {
        $key = '';

        for ($i = 1; $i < $length; $i++) {
            $key .= mt_rand(0,9);
        }

        $key .= mt_rand(1,9);

        return $key;
    }

    /**
     * Displays an XRDS document, or redirects to it.
     * By default, it detects whether it should display or redirect automatically.
     * @param bool|null $force When true = always display, false = always redirect.
     */
    protected function xrds($force = null)
    {
        if ($force) {
            print $this->getXrdsContent();

            exit;
        }

        if (false === $force) {
            header('X-XRDS-Location: '.$this->getXrdsLocation());

            return;
        }

        if (
            array_key_exists('xrds', $this->getParams()) ||
            (false !== stripos($this->getEnv('HTTP_ACCEPT'), 'application/xrds+xml'))
        ) {
            header('Content-Type: application/xrds+xml');
            print $this->getXrdsContent();

            exit;
        }

        header('X-XRDS-Location: '.$this->getXrdsLocation());
    }

    /**
     * Returns the content of the XRDS document
     *
     * @return String The XRDS document.
     */
    protected function getXrdsContent()
    {
        $type = $this->selectId ? 'server' : 'signon';
        $type = sprintf('%s/%s', $this->spec()->ns, $type);
        $uri = $this->getServerLocation();

        return join("\n", [
            '<?xml version="1.0" encoding="UTF-8"?>';
            '<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)">';
            '<XRD>';
            '    <Service>';
            '        <Type>'.$type.'</Type>',
            '        <URI>'.$uri.'</URI>',
            '    </Service>',
            '</XRD>',
            '</xrds:XRDS>'
        ]);
    }

    /**
     * Does everything that a provider has to -- in one function.
     */
    public function server()
    {
        if ($paramAssocHandle = $this->getParam('openid_assoc_handle')) {
            $this->assoc = $this->getAssoc($paramAssocHandle);

            if (isset($this->assoc['data'])) {
                # We have additional data stored for setup.
                $params = $this->getParams();
                $params += $this->assoc['data'];
                $this->setParams($params);
                unset($this->assoc['data']);
            }
        }

        if ($this->getParam('openid_ns') === $this->spec()->ns) {
            $paramOpenIdMode = $this->getParam('openid_mode');

            if (!$paramOpenIdMode) {
                $this->errorResponse();
            }

            switch($paramOpenIdMode) {
                case 'checkid_immediate':
                case 'checkid_setup':

                    $this->checkRealm();
                    # We support AX xor SREG.
                    $attributes = $this->ax();

                    if (!$attributes) {
                        $attributes = $this->sreg();
                    }

                    # Even if some user is authenticated, we need to know if it's
                    # the same one that want's to authenticate.
                    # Of course, if we use select_id, we accept any user.
                    if (($identity = $this->checkId($this->getParam('openid_realm'), $attrValues)) &&
                        ($this->select_id || $identity === $this->getParam('openid_identity')))
                    {
                        $this->positiveResponse($identity, $attrValues);
                    }

                    elseif ('checkid_immediate' === $paramOpenIdMode)
                    {
                        $this->redirect($this->response([
                            'openid.mode' => 'setup_needed'
                        ]));
                    }

                    else
                    {
                        if (!$this->assoc) {
                            $this->generateAssociation();
                            $this->assoc['private'] = true;
                        }

                        $this->assoc['data'] = $this->getParams();
                        $this->setAssoc($this->assoc['handle'], $this->assoc);

                        $this->setup(
                            $this->getParam('openid_identity'),
                            $this->getParam('openid_realm'),
                            $this->assoc['handle'],
                            $attributes
                        );
                    }

                    break;

                case 'associate':

                    $this->associate();

                    break;

                case 'check_authentication':

                    $this->checkRealm();

                    if ($this->verify()) {
                        print "ns:".$this->spec()->ns."\nis_valid:true";

                        if (false !== strpos($this->getParam('openid_signed'),'invalidate_handle')) {
                            print "\ninvalidate_handle:".$this->getParam('openid_invalidate_handle');
                        }
                    } else {
                        print "ns:".$this->spec()->ns."\nis_valid:false";
                    }

                    exit;
                    break;

                default:

                    $this->errorResponse();
            }
        } else {
            $this->xrds();
        }
    }

    protected function checkRealm()
    {
        $paramReturnTo = $this->getParam('openid_return_to');
        $paramRealm = $this->getParam('openid_realm');

        if (!$paramReturnTo || !$paramRealm) {
            $this->errorResponse();
        }

        $realm = str_replace('\*', '[^/]', preg_quote($paramRealm));

        if (!preg_match("#^$realm#", $paramReturnTo)) {
            $this->errorResponse();
        }
    }

    protected function ax()
    {
        # Namespace prefix that the fields must have.
        $ns = 'http://axschema.org/';

        # First, we must find out what alias is used for AX.
        # Let's check the most likely one
        $alias = null;

        if ('http://openid.net/srv/ax/1.0' === $this->getParam('openid_ns_ax')) {
            $alias = 'ax';
        } else {
            foreach ($this->getParams() as $paramName => $paramValue) {
                if (
                    'http://openid.net/srv/ax/1.0' === $paramValue &&
                    preg_match('/openid[_.]ns[_.](.+)/', $paramName, $m)
                ) {
                    $alias = str_replace('.', '_', $m[1]);
                    break;
                }
            }
        }

        if (!$alias) {
            return null;
        }

        $fields = [];

        # Now, we must search again, this time for field aliases
        foreach ($this->getParams() as $paramName => $paramValue) {
            $paramName = str_replace('.', '_', $paramName);

            if (
                (false === strpos($paramName, 'openid_'.$alias.'_type')) ||
                (false === strpos($paramValue, $ns))
            ) {
                continue;
            }

            $paramName = substr($paramName, strlen('openid_'.$alias.'_type_'));
            $paramValue = substr($paramValue, strlen($ns));
            $fields[$paramName] = $paramValue;
        }

        # Then, we find out what fields are required and optional
        $required = $ifAvailable = [];

        foreach(['required','ifAvailable'] as $type) {
            $paramValue = $this->getParam("openid_{$alias}_{$type}");

            if (!$paramValue)) {
                continue;
            }

            $attributes = preg_split('/\s*,\s*/', $paramValue);

            foreach ($attributes as $attr) {
                if (empty($fields[$attr])) {
                    # There is an undefined field here, so we ignore it.
                    continue;
                }

                ${$type}[] = $fields[$attr];
            }
        }

        $this->setParam('ax', true);

        return [
            'required' => $required,
            'optional' => $ifAvailable
        ];
    }

    protected function sreg()
    {
        $sregToAx = array_flip($this->getAxToSregMap());
        $attributes = ['required' => [], 'optional' => []];
        $paramSregRequired = $this->getParam('openid_sreg_required');
        $paramSregOptional = $this->getParam('openid_sreg_optional');

        if (!$paramSregRequired && !$paramSregOptional) {
            return $attributes;
        }

        $required = $optional = [];

        foreach (['required', 'optional'] as $type) {
            $paramValue = $this->getParam('openid_sreg_'.$type, '');

            foreach (preg_split('/\s*,\s*/', $paramValue) as $attr) {
                if (empty($sregToAx[$attr])) {
                    # Undefined attribute in SREG request.
                    # Shouldn't happen, but we check anyway.
                    continue;
                }

                $attributes[$type][] = $sreg_to_ax[$attr];
            }
        }
        return $attributes;
    }

    /**
     * Aids a relying party in assertion verification.
     *
     * @return bool Information whether the verification suceeded.
     */
    protected function verify()
    {
        # Firstly, we need to make sure that there's an association.
        # Otherwise the verification will fail,
        # because we've signed assoc_handle in the assertion
        if (empty($this->assoc)) {
            return false;
        }

        # Next, we check that it's a private association,
        # i.e. one made without RP input.
        # Otherwise, the RP shouldn't ask us to verify.
        if (empty($this->assoc['private'])) {
            return false;
        }

        # Now we have to check if the nonce is correct, to prevent replay attacks.
        if ($this->getParam('openid_response_nonce') !== $this->assoc['nonce']) {
            return false;
        }

        # Getting the signed fields for signature.
        $sig = [];
        $signed = preg_split('/\s*,\s*/', $this->getParam('openid_signed', ''));

        foreach ($signed as $field) {
            $name = strtr($field, '.', '_');
            $fieldValue = $this->getParam('openid_'.$name);
            if (!$fieldValue) {
                return false;
            }
            $sig[$field] = $fieldValue;
        }

        # Computing the signature and checking if it matches.
        $sig = $this->keyValueForm($sig);
        $encoded = base64_encode(hash_hmac(
            $this->assoc['hash'],
            $sig,
            $this->assoc['mac'],
            true
        ));

        if ($this->getParam('openid_sig') !== $encoded) {
            return false;
        }

        # Clearing the nonce, so that it won't be used again.
        $this->assoc['nonce'] = null;

        if (empty($this->assoc['private'])) {
            # Commiting changes to the association.
            $this->setAssoc($this->assoc['handle'], $this->assoc);
        } else {
            # Private associations shouldn't be used again, se we can as well delete them.
            $this->delAssoc($this->assoc['handle']);
        }

        # Nothing has failed, so the verification was a success.
        return true;
    }

    /**
     * Performs association with an RP.
     */
    protected function associate()
    {
        # Rejecting no-encryption without TLS.
        if (
            !filter_var($this->getEnv('HTTPS'), FILTER_VALIDATE_BOOLEAN) &&
            $this->getParam('openid_session_type') == 'no-encryption'
        ) {
            $this->directErrorResponse();
        }

        # Creating the association
        $this->assoc = [];
        $this->assoc['hash'] = ('HMAC-SHA256' === $this->getParam('openid_assoc_type'))
            ? 'sha256'
            : 'sha1';
        $this->assoc['handle'] = $this->assocHandle();

        # Getting the shared secret
        if ($this->getParam('openid_session_type') == 'no-encryption') {
            $sharedSecret = $this->sharedSecret($this->assoc['hash']);
            $this->assoc['mac'] = base64_encode($sharedSecret);
        } else {
            $this->dh();
        }

        # Preparing the direct response...
        $response = [
            'ns' => $this->spec()->ns,
            'assoc_handle' => $this->assoc['handle'],
            'assoc_type' => $this->getParam('openid_assoc_type'),
            'session_type' => $this->getParam('openid_session_type'),
            'expires_in' => $this->getAssocLifetime()
        ];

        if (isset($this->assoc['dh_server_public'])) {
            $response['dh_server_public'] = $this->assoc['dh_server_public'];
            $response['enc_mac_key'] = $this->assoc['mac'];
        } else {
            $response['mac_key'] = $this->assoc['mac'];
        }

        print $this->keyValueForm($response);
        exit;
    }

    /**
     * Creates a private association.
     */
    protected function generateAssociation()
    {
        # We use sha1 by default.
        $this->assoc = [];
        $this->assoc['hash'] = 'sha1';
        $this->assoc['mac'] = $this->sharedSecret('sha1');
        $this->assoc['handle'] = $this->assocHandle();
    }

    /**
     * Encrypts the MAC key using DH key exchange.
     */
    protected function dh()
    {
        $paramModulus = $this->getParam('openid_dh_modulus');
        $paramDhGen = $this->getParam('openid_dh_gen');
        $paramDhConsumerPublic = $this->getParam('openid_dh_consumer_public');

        if (!$paramModulus) {
            $this->setParam('openid_dh_modulus', $this->spec()->defaultModulus);
        }

        if ($paramDhGen) {
            $this->setParam('openid_dh_gen', $this->spec()->defaultGen);
        }

        if (!$paramDhConsumerPublic) {
            $this->directErrorResponse();
        }

        $modulus = $this->b64dec($this->getParam('openid_dh_modulus'));
        $gen = $this->b64dec($this->getParam('openid_dh_gen'));
        $consumerKey = $this->b64dec($this->getParam('openid_dh_consumer_public'));
        $privateKey = $this->keyGen(strlen($modulus));
        $publicKey = $this->powmod($gen, $privateKey, $modulus);
        $ss = $this->powmod($consumerKey, $privateKey, $modulus);
        $mac = $this->xor(
            hash($this->assoc['hash'], $ss, true),
            $this->sharedSecret($this->assoc['hash'])
        );
        $this->assoc['dh_server_public'] = $this->decb64($publicKey);
        $this->assoc['mac'] = base64_encode($mac);
    }

    /**
     * XORs two strings.
     *
     * @param String $a
     * @param String $b
     *
     * @return String $a ^ $b
     */
    protected function xor($a, $b)
    {
        $length = strlen($a);

        for($i = 0; $i < $length; $i++) {
            $a[$i] = $a[$i] ^ $b[$i];
        }

        return $a;
    }

    /**
     * Prepares an indirect response url.
     *
     * @param array $params Parameters to be sent.
     */
    protected function response($params)
    {
        $params += ['openid.ns' => $this->spec()->ns];

        return $this->getParam('openid_return_to').
             (strpos($this->getParam('openid_return_to'), '?') ? '&' : '?').
             http_build_query($params, '', '&');
    }

    /**
     * Outputs a direct error.
     */
    protected function errorResponse()
    {
        if (!empty($this->getParam('openid_return_to'))) {
            $this->redirect($this->response([
                'openid.mode' => 'error',
                'openid.error' => 'Invalid request',
            ]));
        } else {
            header('HTTP/1.1 400 Bad Request', true, 400);

            print $this->keyValueForm([
                'ns' => $this->spec()->ns,
                'error' => 'Invalid request',
            ]);
        }

        exit;
    }

    /**
     * Sends an positive assertion.
     *
     * @param String $identity the OP-Local Identifier that is being authenticated.
     * @param Array $attributes User attributes to be sent.
     */
    protected function positiveResponse($identity, array $attributes)
    {
        # We generate a private association if there is none established.
        if (!$this->assoc) {
            $this->generateAssociation();
            $this->assoc['private'] = true;
        }

        # We set openid.identity (and openid.claimed_id if necessary) to our $identity
        $paramIdentity = $this->getParam('openid_identity');
        $paramClaimedId = $this->getParam('openid_claimed_id');

        if ($paramIdentity === $paramClaimedId || $this->selectId) {
            $this->setParam('openid_claimed_id', $identity);
        }

        $this->setParam('openid_identity', $identity);

        # Preparing fields to be signed
        $params = [
            'op_endpoint' => $this->getServerLocation(),
            'claimed_id' => $this->getParam('openid_claimed_id'),
            'identity' => $this->getParam('openid_identity'),
            'return_to' => $this->getParam('openid_return_to'),
            'realm' => $this->getParam('openid_realm'),
            'response_nonce' => gmdate("Y-m-d\TH:i:s\Z"),
            'assoc_handle' => $this->assoc['handle'],
        ];

        $params += $this->responseAttributes($attributes);

        # Has the RP used an invalid association handle?
        $paramAssocHandle = $this->getParam('openid_assoc_handle');
        if ($paramAssocHandle && ($paramAssocHandle !== $this->assoc['handle'])) {
            $params['invalidate_handle'] = $paramAssocHandle;
        }

        # Signing the $params
        $sig = hash_hmac(
            $this->assoc['hash'],
            $this->keyValueForm($params),
            $this->assoc['mac'],
            true
        );

        $req = [
            'openid.mode' => 'id_res',
            'openid.signed' => join(',', array_keys($params)),
            'openid.sig' => base64_encode($sig),
        ];

        # Saving the nonce and commiting the association.
        $this->assoc['nonce'] = $params['response_nonce'];
        $this->setAssoc($this->assoc['handle'], $this->assoc);

        # Preparing and sending the response itself
        foreach ($params as $name => $value) {
            $req['openid.'.$name] = $value;
        }

        $this->redirect($this->response($req));
    }

    /**
     * Prepares an array of attributes to send
     *
     * @param array $attributes
     */
    protected function responseAttributes(array $attributes = [])
    {
        if (!$attributes) {
            return [];
        }

        $ns = 'http://axschema.org/';
        $response = [];

        if ($this->getParam('ax')) {
            $response['ns.ax'] = 'http://openid.net/srv/ax/1.0';

            foreach ($attributes as $name => $value) {
                $alias = strtr($name, '/', '_');
                $response['ax.type.'.$alias] = $ns.$name;
                $response['ax.value.'.$alias] = $value;
            }

            return $response;
        }

        $axToSregMap = $this->getAxToSregMap();

        foreach ($attributes as $name => $value) {
            if (isset($axToSregMap[$name])) {
                $response['sreg.'.$axToSregMap[$name]] = $value;
            }
        }

        return $response;
    }

    /**
     * Encodes fields in key-value form.
     *
     * @param Array $params Fields to be encoded.
     *
     * @return String $params in key-value form.
     */
    protected function keyValueForm(array $params)
    {
        $str = '';

        foreach ($params as $name => $value) {
            $str .= sprintf("%s:%s\n", $name, $value);
        }

        return $str;
    }

    /**
     * Responds with an information that the user has canceled authentication.
     */
    protected function cancel()
    {
        $this->redirect($this->response(['openid.mode' => 'cancel']));
    }

    /**
     * Converts base64 encoded number to it's decimal representation.
     *
     * @param String $str base64 encoded number.
     *
     * @return String Decimal representation of that number.
     */
    protected function b64dec($str)
    {
        $bytes = unpack('C*', base64_decode($str));
        $n = 0;

        foreach ($bytes as $byte) {
            $n = $this->math()->add($this->math()->mul($n, 256), $byte);
        }

        return $n;
    }

    /**
     * Complements b64dec.
     *
     * @param integer $num
     *
     * @return string Encoded representation
     */
    protected function decb64($num)
    {
        $bytes = [];

        while ($num) {
            array_unshift($bytes, $this->math()->mod($num, 256));
            $num = $this->div($num, 256);
        }

        if ($bytes && $bytes[0] > 127) {
            array_unshift($bytes,0);
        }

        array_unshift($bytes, 'C*');
        return base64_encode(call_user_func_array('pack', $bytes));
    }

    /**
     * Static access to throwing an error.
     *
     * @param string $error The Error Message
     */
    protected static function raise($error)
    {
        # Oooh, I'm bad :)
        eval('class LightOpenIdException extends Exception {}');
        throw new \LightOpenIdException($error);
    }

}
