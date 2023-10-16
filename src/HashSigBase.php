<?php
namespace dynoser\hashsig;

class HashSigBase {
    public string $srcPath = '';
    public string $hashSigFile = '';
    const HASHSIG_FILE_INDEX = '';
    const HASHSIG_FILE_EXT = '.hashsig';
    const DEFAULT_HASH_ALG = 'sha256';
    const DEFAULT_HASH_HEX_LEN = 64;
    public string $hashAlgName = self::DEFAULT_HASH_ALG;
    public int $hashHexLen = self::DEFAULT_HASH_HEX_LEN;

    public $canSign = false;
    public $ownSignerObj = null;
    public $ownPubKeyBin = null;

    public function setDir(string $srcPath, string $hashSigFile = null): void
    {
        $hnRp = \realpath($srcPath);
        if (empty($hnRp)) {
            throw new \InvalidArgumentException("Directory $srcPath does not exist.");
        }
        $this->srcPath = \strtr($hnRp, '\\', '/');
        
        if ($hashSigFile) {
            $hashSigFile = \strtr($hashSigFile, '\\', '/');
            if (false === \strpos($hashSigFile, '/')) {
                $hashSigFile = $this->srcPath . '/' . $hashSigFile;
            }
            if (false === \strpos($hashSigFile, '.')) {
                $hashSigFile .= self::HASHSIG_FILE_EXT;
            }
            $this->hashSigFile = $hashSigFile;
        } else {
            $this->hashSigFile = $this->srcPath . '/' . self::HASHSIG_FILE_INDEX . self::HASHSIG_FILE_EXT;
        }
    }

    public function setOwnSignerObj($ownSignerObj = null) {
        $this->canSign = false;
        if (\is_null($ownSignerObj)) {
            $ownSignerObj = null;
            $this->ownPubKeyBin = null;
        } else {
            if (!\property_exists($ownSignerObj, 'pub_key') || !\method_exists($ownSignerObj, 'verifySign')) {
                throw new \Exception("Invalid KeySignerObj object, requires verifySign methods and pub_key property.");
            }
            $this->ownPubKeyBin = $ownSignerObj->pub_key;
            if (\property_exists($ownSignerObj, 'can_sign')) {
                $this->canSign = $ownSignerObj->can_sign;
            }
        }
        $this->ownSignerObj = $ownSignerObj;
    }

    public function setHashAlg(string $hashAlg = null): void
    {
        if ($hashAlg && $hashAlg !== self::DEFAULT_HASH_ALG) {
            $testHash = \hash($hashAlg, 'test');
            if (!$testHash) {
                throw new \InvalidArgumentException("Hash $hashAlg is not supported.");
            }
            $hashHexLen = \strlen($testHash);
        } else {
            $hashAlg = self::DEFAULT_HASH_ALG;
            $hashHexLen = self::DEFAULT_HASH_HEX_LEN;
        }

        $this->hashAlgName = $hashAlg;
        $this->hashHexLen = $hashHexLen;
    }
    
    public function getHashAlg() {
        return $this->hashAlgName;
    }

    public function unpackHashSignedStr(
        string $hashSignedStr,
        $leftPartOfKey = true,
        bool $doNotVerifyHash = false,
        bool $doNotVerifySign = false
    ): ?array {
        if (true === $leftPartOfKey) {
            $leftPartOfKey = $this->srcPath . '/';
        }
        // set EOL to canonical
        if (false !== \strpos($hashSignedStr, "\r")) {
            $hashSignedStr = (false !== \strpos($hashSignedStr, "\n\r"))
            ? \strtr($hashSignedStr, ["\r" => '']) : \strtr($hashSignedStr, "\r", "\n");
        }
        
        $firstStrEndPos = \strpos($hashSignedStr, "\n");
        $signStr = \substr($hashSignedStr, 0 , $firstStrEndPos);
        $signArr = explode('~', $signStr);
        if (count($signArr) < 5) {
            return null;
        }
        $tmpArr = [];
        foreach($signArr as $helmlStr) {
            $i = \strpos($helmlStr, ':');
            if ($i) {
                $key = \trim(\substr($helmlStr, 0, $i));
                $tmpArr[$key] = \trim(\substr($helmlStr, $i+1));
            }
        }

        foreach(['hashsig'] as $key) {
            if (empty($tmpArr[$key])) {
                return null;
            }
        }
        
        $hashAlg = $this->hashAlgName;

        foreach($tmpArr as $name => $value) {
            switch ($name) {
            case 'hashsig':
                $hashHex = $value;
                break;
            case 'filescnt':
                $filesCnt = $value;
                break;
            case 'pubkey':
                $keyPubB64 = $value;
                break;
            case 'signature':
                $signatureB64 = $value;
                break;
            case 'hashalg':
                $hashAlg = $value;
                break;
            case 'signalg':
                if ($value !== 'ed25519') {
                    throw new \Exception("Ed25519 signature algorithm implemented only");
                }
                break;
            }
        }

        $sumSt = \trim(\substr($hashSignedStr, $firstStrEndPos + 1));
        if (!$doNotVerifyHash) {
            $chkHashHex = \hash($hashAlg, $sumSt);
            if ($hashHex !== $chkHashHex) {
                return null;
            }
        }
        $this->setHashAlg($hashAlg);

        $keyPubBin = \base64_decode($keyPubB64);
        if (!\is_string($keyPubBin) || \strlen($keyPubBin) < 32) {
            return null;
        }
        
        $signatureBin = \base64_decode($signatureB64);
        if (!\is_string($signatureBin) || \strlen($signatureBin) < 64) {
            return null;
        }

        // Verify signature
        if (!$doNotVerifySign) {
            if ($this->ownSignerObj) {
                $signIsOk = $this->ownSignerObj->verifySign($signatureBin, $hashHex, $keyPubBin);
            } elseif (\function_exists('sodium_crypto_sign_verify_detached')) {
                $signIsOk = \sodium_crypto_sign_verify_detached($signatureBin, $hashHex, $keyPubBin);
            } else {
                throw new \Exception("No signature verification method");
            }
            
            if (!$signIsOk) {
                throw new \Exception("Invalid signature");
            }
        }

        $resultArr = [];
        $arr = \explode("\n", $sumSt);
        foreach($arr as $st) {
            $i = \strpos($st, ':');
            if (!$i) continue;
            $j = \strpos($st, ' ', $i + 2);
            if (!$j) continue;
            $fileShortName = \substr($st, 0, $i);
            $fileHashHex = \substr($st, $i + 2, $j - $i - 2);
            $resultArr[$leftPartOfKey . $fileShortName] = [$fileShortName, $fileHashHex, \substr($st, $j+1)];
        }

        return $resultArr;
    }
}