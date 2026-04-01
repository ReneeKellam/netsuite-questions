<?php
require_once __DIR__ . '/env.php';
EnvLoader::load(__DIR__ . '/../.env');

class NetSuiteClient {
    private $accountId;
    private $clientId;
    private $clientSecret;
    private $publicCertPath;
    private $privateCertPath;
    private $accessToken;
    private $tokenExpiry;
    private $certificateId;

    /** Debug logging */
    private function logDebug($message) {
        $logFile = __DIR__ . '/../logs/netsuite-api.log';
        $logDir = dirname($logFile);
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }
        $timestamp = date('Y-m-d H:i:s');
        file_put_contents($logFile, "[$timestamp] $message\n", FILE_APPEND | LOCK_EX);
    }

    public function __construct() {
        $this->logDebug("\n===========Initializing NetSuiteClient ".date('Y-m-d H:i:s')."=============\n");
        $this->accountId = EnvLoader::get('NETSUITE_ACCOUNT_ID') ?? null;
        $this->clientId = EnvLoader::get('NETSUITE_CLIENT_ID') ?? null;
        $this->clientSecret = EnvLoader::get('NETSUITE_CLIENT_SECRET') ?? null;
        $this->publicCertPath = EnvLoader::get('NETSUITE_PUBLIC_CERT_PATH') ?? null;
        $this->privateCertPath = EnvLoader::get('NETSUITE_PRIVATE_CERT_PATH') ?? null;
        $this->certificateId = EnvLoader::get('NETSUITE_CERTIFICATE_ID') ?? null;
        
        if (empty($this->accountId) || empty($this->clientId) || empty($this->clientSecret) || empty($this->publicCertPath) || empty($this->privateCertPath) || empty($this->certificateId)) {
            $this->logDebug("Error: Missing required configuration variables");
            throw new Exception("Missing required configuration variables. Please check your .env file.");
        } else {
            $this->logDebug("All required configuration variables are set.");
        }
    }

    /** Generate JWT Client Assertion */
    private function generateClientAssertion() {
        $this->logDebug("Starting JWT generation...");
        
        $now = time();
        $exp = $now + 300; // 5 minutes expiration
        
        $this->logDebug("JWT timing - Now: $now, Expires: $exp");

        // Load private key file
        $privateKeyPath = __DIR__ . '/../' . $this->privateCertPath;
        $this->logDebug("Looking for private key at: $privateKeyPath");
        
        if (!file_exists($privateKeyPath)) {
            throw new Exception("Private key file not found: $privateKeyPath");
        }
        
        $privateKeyContent = file_get_contents($privateKeyPath);
        if (!$privateKeyContent) {
            throw new Exception("Failed to read private key file");
        }
        
        $this->logDebug("Private key file loaded, length: " . strlen($privateKeyContent));
        
        // Load the private key
        $privateKey = openssl_pkey_get_private($privateKeyContent);
        if (!$privateKey) {
            $this->logDebug("OpenSSL error: " . openssl_error_string());
            throw new Exception("Failed to load private key: " . openssl_error_string());
        }
        
        // Get key details
        $keyDetails = openssl_pkey_get_details($privateKey);
        $keyType = $keyDetails['type'] ?? null;
        $keyBits = $keyDetails['bits'] ?? 0;
        
        $this->logDebug("Key type: " . ($keyType === OPENSSL_KEYTYPE_RSA ? 'RSA' : ($keyType === OPENSSL_KEYTYPE_EC ? 'EC' : 'Unknown')));
        $this->logDebug("Key bits: " . $keyBits);
        
        // Determine algorithm based on key type and size
        $algorithm = null;
        $opensslAlgo = null;
        
        $algorithm = 'ES512';
        $opensslAlgo = OPENSSL_ALGO_SHA512;

        $this->logDebug("Using algorithm: $algorithm");
        
        // JWT Header
        $header = [
            'typ' => 'JWT',
            'alg' => $algorithm,
            'kid' => $this->certificateId
        ];
        
        // JWT Payload - NetSuite format
        $payload = [
            'iss' => $this->clientId,
            'sub' => $this->clientId,
            'aud' => "https://{$this->accountId}.suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/token",
            'exp' => $exp,
            'iat' => $now,
            'jti' => bin2hex(random_bytes(16))
        ];
        
        // Base64url encode header and payload
        $headerEncoded = $this->base64urlEncode(json_encode($header, JSON_UNESCAPED_SLASHES));
        $payloadEncoded = $this->base64urlEncode(json_encode($payload, JSON_UNESCAPED_SLASHES));
        
        $this->logDebug("Header encoded length: " . strlen($headerEncoded));
        $this->logDebug("Payload encoded length: " . strlen($payloadEncoded));
        
        // Create signature data
        $signatureData = $headerEncoded . '.' . $payloadEncoded;
        
        // Sign the JWT
        $signature = '';
        $success = openssl_sign($signatureData, $signature, $privateKey, $opensslAlgo);
        
        if (!$success) {
            $this->logDebug("Signing failed, OpenSSL error: " . openssl_error_string());
            throw new Exception("Failed to sign JWT: " . openssl_error_string());
        }
        
        $this->logDebug("Signature created successfully, length: " . strlen($signature));
        
        // Base64url encode signature
        $signatureEncoded = $this->base64urlEncode($signature);
        $this->logDebug("Signature encoded length: " . strlen($signatureEncoded));
        
        // Create final JWT
        $jwt = $headerEncoded . '.' . $payloadEncoded . '.' . $signatureEncoded;
        
        $this->logDebug("Final JWT length: " . strlen($jwt));
        $this->logDebug("JWT algorithm used: $algorithm");
        $this->logDebug("JWT created successfully");
        
        return $jwt;
    }

    /** Base64URL encoding (URL-safe base64 without padding) */
    private function base64urlEncode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /** Get OAuth 2.0 access token using client credentials flow with JWT assertion */
    private function getAccessToken() {
        $this->logDebug("Starting token request...");
        
        // Check if we have a valid token
        if ($this->accessToken && $this->tokenExpiry && time() < $this->tokenExpiry) {
            $this->logDebug("Using cached access token");
            return $this->accessToken;
        }
        
        $tokenUrl = "https://{$this->accountId}.suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/token";
        
        // Generate JWT
        try {
            $assertion = $this->generateClientAssertion();
            $this->logDebug("JWT assertion generated successfully");
        } catch (Exception $e) {
            $this->logDebug("JWT generation failed: " . $e->getMessage());
            throw $e;
        }
        
        // Build POST parameters
        $parameters = [
            'grant_type' => 'client_credentials',
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $assertion
        ];
               
        // Ensure proper URL encoding
        $postData = http_build_query($parameters, '', '&', PHP_QUERY_RFC1738);
        $this->logDebug("POST data length: " . strlen($postData));
        
        // HTTP client request
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $tokenUrl,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $postData,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/x-www-form-urlencoded',
                'Accept: application/json',
                'User-Agent: NetSuite-PHP-Client/1.0',
                'Content-Length: ' . strlen($postData)
            ],
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_VERBOSE => false,
            CURLOPT_FOLLOWLOCATION => false
        ]);
        
        $this->logDebug("Making HTTP POST request...");
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $contentType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        $error = curl_error($ch);
        curl_close($ch);
        
        $this->logDebug("HTTP Response Code: $httpCode");
        $this->logDebug("Content-Type: $contentType");
        $this->logDebug("Response: $response");
        
        if ($error) {
            $this->logDebug("cURL error: $error");
            throw new Exception("cURL error: $error");
        }
        
        if ($httpCode !== 200) {
            $this->logDebug("HTTP error occurred");
            
            // Try to decode error response
            $errorData = json_decode($response, true);
            if ($errorData) {
                $this->logDebug("Parsed error response: " . json_encode($errorData));
                
                if (isset($errorData['error_description'])) {
                    throw new Exception("NetSuite error: {$errorData['error']} - {$errorData['error_description']}");
                } elseif (isset($errorData['error'])) {
                    throw new Exception("NetSuite error: {$errorData['error']}");
                }
            }
            
            throw new Exception("HTTP error: $httpCode. Response: $response");
        }
        
        $tokenData = json_decode($response, true);
        
        if (!$tokenData || !isset($tokenData['access_token'])) {
            $this->logDebug("Invalid token response format");
            throw new Exception("Invalid token response: $response");
        }
        
        $this->accessToken = $tokenData['access_token'];
        $this->tokenExpiry = time() + ($tokenData['expires_in'] ?? 3600) - 60;
        
        $this->logDebug("Token obtained successfully, expires in: " . ($tokenData['expires_in'] ?? 'unknown') . " seconds");
        
        return $this->accessToken;
    }

    /** Test the connection */
    public function testConnection() {
        $this->logDebug("=== Starting NetSuite Connection Test ===");
        try {
            $token = $this->getAccessToken();
            
            $this->logDebug("=== Connection Test Successful ===");
            return [
                'success' => true,
                'message' => 'Connection successful - token obtained',
                'token_preview' => substr($token, 0, 10) . '...'
            ];
        } catch (Exception $e) {
            $this->logDebug("=== Connection Test Failed: " . $e->getMessage() . " ===");
            return [
                'success' => false,
                'message' => $e->getMessage()
            ];
        }
    }
}
?>
