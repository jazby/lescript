<?php
namespace Jazby\Lescript;

class Lescript
{
    const CHALLENGE_URL = '.well-known/acme-challenge';
    const MAX_ATTEMPTS_LOOP_LIMIT = 60;
    public $ca = 'https://acme-v01.api.letsencrypt.org';
    // public $ca = 'https://acme-staging.api.letsencrypt.org'; // testing
    public $license = 'https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf';
    public $countryCode = 'CZ';
    public $state = "Czech Republic";
    /** @var callable $domainChallengeStartCallback function(array $domain) */
    protected $domainChallengeStartCallback;
    /** @var callable $domainChallengeStartCallback function(array $domain) */
    protected $domainChallengeEndCallback;
    private $certificatesDir;
    private $webRootDir;
    /** @var \Psr\Log\LoggerInterface */
    private $logger;
    private $client;
    private $accountKeyPath;
    private $fileClient;

    public function __construct($certificatesDir, $webRootDir, $logger = null)
    {
        $this->certificatesDir = $certificatesDir;
        $this->webRootDir = $webRootDir;
        $this->logger = $logger;
        $this->client = new Client($this->ca);
        $this->fileClient = new FileClient();
        $this->accountKeyPath = $certificatesDir . '/_account/private.pem';
    }

    public function initAccount()
    {
        if (!is_file($this->accountKeyPath)) {

            // generate and save new private key for account
            // ---------------------------------------------

            $this->log('Starting new account registration');
            $this->generateKey(dirname($this->accountKeyPath));
            $this->postNewReg();
            $this->log('New account certificate registered');
        } else {

            $this->log('Account already registered. Continuing.');
        }
    }

    public function signDomains(array $domains, $reuseCsr = false)
    {
        $this->log('Starting certificate generation process for domains');

        // start domains authentication
        // ----------------------------
        foreach ($domains as &$domain) {
            // remap array to request format -> for future use
            if (is_array($domain) && !isset($domain['name'])) {
                throw new \RuntimeException('Please fill input domains array correctly (domain.tld, www.domain.tld etc.)');
            } elseif (!is_array($domain)) {
                $domain = ['name' => $domain];
            }

            if (filter_var($domain['name'], FILTER_VALIDATE_URL) !== false) {
                throw new \RuntimeException('Please fill input domains without protocol (domain.tld instead od http(s)://domain.tld etc.)');
            }

            // 0. if you need action before sign started, calling callback method
            if (is_callable($this->domainChallengeStartCallback)) {
                call_user_func($this->domainChallengeStartCallback, $domain);
            }

            // 1. getting available authentication options
            // -------------------------------------------
            $challenge = $this->getChallengeToken($domain);

            $location = $this->client->getLastLocation();

            // 2. saving authentication token for web verification
            // ---------------------------------------------------
            $payload = $this->uploadToken($domain, $challenge['token']);

            // 3. verification process itself
            // -------------------------------
            try {
                $this->verifyDomainToken($domain, $challenge['token'], $payload);
            } catch (\Exception $e) {
                throw $e;
            }

            $this->log("Sending request to challenge");

            // send request to challenge
            $result = $this->signedRequest(
                $challenge['uri'],
                [
                    "resource" => "challenge",
                    "type" => "http-01",
                    "keyAuthorization" => $payload,
                    "token" => $challenge['token']
                ]
            );

            // waiting loop
            $i = 0;
            do {
                if (++$i >= self::MAX_ATTEMPTS_LOOP_LIMIT) {
                    throw new \RuntimeException("Verification ended with error: Max try limit reached");
                }
                if (empty($result['status']) || $result['status'] == "invalid") {
                    throw new \RuntimeException("Verification ended with error: " . json_encode($result));
                }
                $ended = !($result['status'] === "pending");

                if (!$ended) {
                    $this->log("Verification pending, sleeping 1s");
                    sleep(1);
                }

                $result = $this->client->get($location);
            } while (!$ended);

            $this->log("Verification ended with status: ${result['status']}");
            $this->removeToken($domain, $challenge['token']);

            // 4. if you need action before sign started, calling callback method
            if (is_callable($this->domainChallengeEndCallback)) {
                call_user_func($this->domainChallengeEndCallback, $domain);
            }
        }

        // requesting certificate
        // ----------------------
        $this->requestCertificate($domains, $reuseCsr);

        $location = $this->client->getLastLocation();

        // waiting loop
        $certificates = [];
        $i = 0;
        while (true) {
            $this->client->getLastLinks();

            $result = $this->client->get($location);

            if ($this->client->getLastCode() == 202) {

                $this->log("Certificate generation pending, sleeping 1s");
                sleep(1);
                continue;
            }
            if ($this->client->getLastCode() == 200) {

                $this->log("Got certificate! YAY!");
                $certificates[] = $this->parsePemFromBody($result);

                foreach ($this->client->getLastLinks() as $link) {
                    $this->log("Requesting chained cert at $link");
                    $result = $this->client->get($link);
                    $certificates[] = $this->parsePemFromBody($result);
                }

                break;
            }
            if (++$i >= self::MAX_ATTEMPTS_LOOP_LIMIT) {
                throw new \RuntimeException("Can't get certificate: Max try limit reached");
            }

            throw new \RuntimeException("Can't get certificate: HTTP code " . $this->client->getLastCode());
        }

        if (empty($certificates)) {
            throw new \RuntimeException('No certificates generated');
        }

        // and save certificates
        $this->saveCertificates($domains, $certificates);

        $this->log("Done.");

        return $certificates;
    }

    private function readPrivateKey($path)
    {
        if (($key = openssl_pkey_get_private('file://' . $path)) === false) {
            throw new \RuntimeException(openssl_error_string());
        }

        return $key;
    }

    private function parsePemFromBody($body)
    {
        $pem = chunk_split(base64_encode($body), 64, "\n");

        return "-----BEGIN CERTIFICATE-----\n" . $pem . "-----END CERTIFICATE-----\n";
    }

    private function getDomainPath($domain)
    {
        return $this->certificatesDir . '/' . $domain . '/';
    }

    private function postNewReg()
    {
        $this->log('Sending registration to letsencrypt server');

        return $this->signedRequest(
            '/acme/new-reg',
            ['resource' => 'new-reg', 'agreement' => $this->license]
        );
    }

    private function generateCSR($privateKey, array $domains)
    {
        $domain = reset($domains)['name'];
        $san = implode(",", array_map(function ($dns) {
            return "DNS:" . $dns['name'];
        }, $domains));
        $tmpConf = tmpfile();
        $tmpConfMeta = stream_get_meta_data($tmpConf);
        $tmpConfPath = $tmpConfMeta["uri"];

        // workaround to get SAN working
        fwrite($tmpConf,
            'HOME = .
RANDFILE = $ENV::HOME/.rnd
[ req ]
default_bits = 2048
default_keyfile = privkey.pem
distinguished_name = req_distinguished_name
req_extensions = v3_req
[ req_distinguished_name ]
countryName = Country Name (2 letter code)
[ v3_req ]
basicConstraints = CA:FALSE
subjectAltName = ' . $san . '
keyUsage = nonRepudiation, digitalSignature, keyEncipherment');

        $csr = openssl_csr_new(
            [
                "CN" => $domain,
                "ST" => $this->state,
                "C" => $this->countryCode,
                "O" => "Unknown",
            ],
            $privateKey,
            [
                "config" => $tmpConfPath,
                "digest_alg" => "sha256"
            ]
        );

        if (!$csr) {
            throw new \RuntimeException("CSR couldn't be generated! " . openssl_error_string());
        }

        openssl_csr_export($csr, $csr);
        fclose($tmpConf);

        $csrPath = $this->getDomainPath($domain) . "/last.csr";
        file_put_contents($csrPath, $csr);

        return $this->getCsrContent($csrPath);
    }

    private function getCsrContent($csrPath)
    {
        $csr = file_get_contents($csrPath);

        preg_match('~REQUEST-----(.*)-----END~s', $csr, $matches);

        return trim(Base64UrlSafeEncoder::encode(base64_decode($matches[1])));
    }

    private function generateKey($outputDirectory)
    {
        $res = openssl_pkey_new([
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
            "private_key_bits" => 4096,
        ]);

        if (!openssl_pkey_export($res, $privateKey)) {
            throw new \RuntimeException("Key export failed!");
        }

        $details = openssl_pkey_get_details($res);

        if (!is_dir($outputDirectory)) {
            @mkdir($outputDirectory, 0700, true);
        }
        if (!is_dir($outputDirectory)) {
            throw new \RuntimeException("Cant't create directory $outputDirectory");
        }

        file_put_contents($outputDirectory . '/private.pem', $privateKey);
        file_put_contents($outputDirectory . '/public.pem', $details['key']);
    }

    private function signedRequest($uri, array $payload)
    {
        $privateKey = $this->readPrivateKey($this->accountKeyPath);
        $details = openssl_pkey_get_details($privateKey);

        $header = [
            "alg" => "RS256",
            "jwk" => [
                "kty" => "RSA",
                "n" => Base64UrlSafeEncoder::encode($details["rsa"]["n"]),
                "e" => Base64UrlSafeEncoder::encode($details["rsa"]["e"]),
            ]
        ];

        $protected = $header;
        $protected["nonce"] = $this->client->getLastNonce();

        $payload64 = Base64UrlSafeEncoder::encode(str_replace('\\/', '/', json_encode($payload)));
        $protected64 = Base64UrlSafeEncoder::encode(json_encode($protected));

        openssl_sign($protected64 . '.' . $payload64, $signed, $privateKey, "SHA256");

        $signed64 = Base64UrlSafeEncoder::encode($signed);

        $data = [
            'header' => $header,
            'protected' => $protected64,
            'payload' => $payload64,
            'signature' => $signed64
        ];

        $this->log("Sending signed request to $uri");

        return $this->client->post($uri, json_encode($data));
    }

    protected function log($message)
    {
        if ($this->logger) {
            $this->logger->info($message);
        } else {
            echo $message . "\n";
        }
    }

    /**
     * @param string $state
     */
    public function setState($state)
    {
        $this->state = $state;
    }

    /**
     * @param string $countryCode
     */
    public function setCountryCode($countryCode)
    {
        $this->countryCode = $countryCode;
    }

    /**
     * @param string $ca
     */
    public function setUrl($ca)
    {
        $this->ca = $ca;
    }

    public function enableTestEnvironment()
    {
        $this->setUrl('https://acme-staging.api.letsencrypt.org');
    }

    /**
     * @param array $domain
     * @return mixed|string
     */
    protected function getChallengeToken(array $domain)
    {
        $this->log("Requesting challenge for ${domain['name']}");

        $response = $this->signedRequest(
            "/acme/new-authz",
            ["resource" => "new-authz", "identifier" => ["type" => "dns", "value" => $domain['name']]]
        );

        // choose http-01 challenge only
        $challenge = array_reduce($response['challenges'], function ($v, $w) {
            return $v ? $v : ($w['type'] == 'http-01' ? $w : false);
        });
        if (!$challenge) {
            throw new \RuntimeException("HTTP Challenge for ${domain['name']} is not available. Whole response: " . json_encode($response));
        }

        $this->log("Got challenge token for ${domain['name']}");

        return $response;
    }

    protected function uploadToken(array $domain, $token)
    {
        $privateAccountKey = $this->readPrivateKey($this->accountKeyPath);
        $accountKeyDetails = openssl_pkey_get_details($privateAccountKey);

        $directory = $this->webRootDir . self::CHALLENGE_URL;
        $tokenPath = $directory . '/' . $token;

        try {
            $this->fileClient->isDirectory($directory);
        } catch (\Exception $e) {
            throw new \RuntimeException("Couldn't create directory to expose challenge: ${tokenPath}");
        }

        $header = [
            // need to be in precise order!
            "e" => Base64UrlSafeEncoder::encode($accountKeyDetails["rsa"]["e"]),
            "kty" => "RSA",
            "n" => Base64UrlSafeEncoder::encode($accountKeyDetails["rsa"]["n"])

        ];
        $payload = $token . '.' . Base64UrlSafeEncoder::encode(hash('sha256', json_encode($header), true));

        $this->fileClient->writeContent($tokenPath, $payload);

        $uri = "http://${domain['name']}/" . self::CHALLENGE_URL . "/${token}";
        $this->log("Token for ${domain['name']} saved at $tokenPath and should be available at $uri");

        return $payload;
    }

    protected function requestCertificate(array $domains, $reuseCsr)
    {
        $domainPath = $this->getDomainPath(reset($domains)['name']);

        // generate private key for domain if not exist
        try {
            $this->fileClient->isFile($domainPath, 'private.pem');
        } catch (\Exception $e) {
            $this->generateKey($domainPath);
        }

        // load domain key
        $privateDomainKey = $this->readPrivateKey($domainPath . '/private.pem');

        $this->client->getLastLinks();

        $csr = $reuseCsr && is_file($domainPath . "/last.csr") ?
            $this->getCsrContent($domainPath . "/last.csr") :
            $this->generateCSR($privateDomainKey, $domains);

        // request certificates creation
        $result = $this->signedRequest(
            "/acme/new-cert",
            ['resource' => 'new-cert', 'csr' => $csr]
        );

        if ($this->client->getLastCode() !== 201) {
            throw new \RuntimeException("Invalid response code: " . $this->client->getLastCode() . ", " . json_encode($result));
        }

        return $result;
    }

    protected function saveCertificates(array $domains, $certificates)
    {
        $domainPath = $this->getDomainPath(reset($domains)['name']);

        $this->log("Saving fullchain.pem");
        $this->fileClient->writeContent($domainPath . '/fullchain.pem', implode("\n", $certificates));

        $this->log("Saving cert.pem");
        $this->fileClient->writeContent($domainPath . '/cert.pem', array_shift($certificates));

        $this->log("Saving chain.pem");
        $this->fileClient->writeContent($domainPath . "/chain.pem", implode("\n", $certificates));
    }

    protected function verifyDomainToken(array $domain, $token, $response)
    {
        $uri = "http://${domain['name']}/" . self::CHALLENGE_URL . "/${token}";

        if ($response !== trim(@file_get_contents($uri))) {
            throw new \RuntimeException("Please check $uri - token not available");
        }
        return true;
    }

    protected function removeToken(array $domain, $token)
    {
        $tokenPath = $this->webRootDir . self::CHALLENGE_URL . '/' . $token;

        $this->fileClient->removeFile($tokenPath);

        $this->log("Token for ${domain['name']} removed from $tokenPath");
    }
}
