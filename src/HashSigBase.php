<?php
namespace dynoser\hashsig;

use \ZipArchive;

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
    
    public array  $lastPkgHeaderArr = [];
    public string $lastSuccessPubKeyBin = '';
    public array  $hashSignedArr = [];
    public string $hashSignedStr = '';
    public $trustKeysObj = null;
    public $writeLogObj = null;

    public $peekContext = null;

    public function setDir(string $srcPath = null, string $hashSigFile = null): void
    {
        if (!$srcPath) {
            $srcPath = $this->srcPath;
        }
        $hnRp = \realpath($srcPath);
        if (empty($hnRp)) {
            throw new \InvalidArgumentException("Directory $srcPath does not exist.");
        }
        $this->srcPath = \strtr($hnRp, '\\', '/');
        
        if ($hashSigFile) {
            $hashSigFile = \strtr($hashSigFile, '\\', '/');
            if (false === \strpos($hashSigFile, '/')) {
                $hashSigFile = $this->srcPath . '/' . \basename($hashSigFile);
            }
            $hashSigExt = self::HASHSIG_FILE_EXT;
            if (\substr($hashSigFile, -\strlen($hashSigExt)) !== $hashSigExt) {
                $hashSigFile .= $hashSigExt;
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
        bool $doNotVerifySign = false,
        array $pkgTrustedKeys = null
    ): ?array {
        if (true === $leftPartOfKey) {
            $leftPartOfKey = $this->srcPath . '/';
        }
        // set EOL to LF
        if (false !== \strpos($hashSignedStr, "\r\n")) {
            $hashSignedStr = \strtr($hashSignedStr, ["\r\n" => "\n"]);
        }
        
        $firstStrEndPos = \strpos($hashSignedStr, "\n");
        if (!$firstStrEndPos) {
            return null;
        }
        $signStr = \substr($hashSignedStr, 0 , $firstStrEndPos);
        $this->hashSignedStr = \trim(\substr($hashSignedStr, $firstStrEndPos + 1));

        if ($signStr === 'hashsig: list') {
            if ($pkgTrustedKeys) {
                throw new \Exception("Signature required because trusted keys are specified");
            }
            // list-mode, no signature or hashes
            $resultArr = [];
            $arr = \explode("\n", $this->hashSignedStr);
            foreach($arr as $st) {
                $i = \strpos($st, ':');
                $fileShortName = \substr($st, 0, $i ? $i : \strlen($st));
                $resultArr[$leftPartOfKey . $fileShortName] = [$fileShortName, '', 0];
            }
            return $resultArr;
        }
        
        $signArr = \explode('~', $signStr);
        if (\count($signArr) < 5) {
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

        $this->lastPkgHeaderArr = $tmpArr;

        if (!$doNotVerifyHash) {
            $chkHashHex = \hash($hashAlg, $this->hashSignedStr);
            if ($hashHex !== $chkHashHex) {
                return null;
            }
        }
        $this->setHashAlg($hashAlg);

        $keyPubBin = empty($keyPubB64) ? '' : \base64_decode($keyPubB64);
        if (!$doNotVerifySign && (!\is_string($keyPubBin) || \strlen($keyPubBin) < 32)) {
            return null;
        }

        if ($pkgTrustedKeys) {
            $isTrusted = false;
            $haveKeys = false;
            foreach($pkgTrustedKeys as $chkPubKey) {
                $l = \strlen($chkPubKey);
                if ($l) {
                    if ($l > 32) {
                        $chkPubKey = (64 === $l) ? \hex2bin($chkPubKey) : \base64_decode($chkPubKey);
                    }
                    if ($chkPubKey === $keyPubBin) {
                        $isTrusted = true;
                        break;
                    } else {
                        $haveKeys = true;
                    }
                }
            }
            if ($haveKeys) {
                if (!$isTrusted && $this->trustKeysObj) {
                    $isTrusted = $this->trustKeysObj->isTrust($keyPubBin);
                }
                if (!$isTrusted) {
                    throw new \Exception("Public key \"$keyPubB64\" is not trusted");
                }
            }
        }
        
        if (!$doNotVerifySign) {
            $signatureBin = \base64_decode($signatureB64);
            if (!\is_string($signatureBin) || \strlen($signatureBin) < 64) {
                return null;
            }

            // Verify signature
            if ($this->ownSignerObj) {
                $signIsOk = $this->ownSignerObj->verifySign($signatureBin, $hashHex, $keyPubBin);
            } elseif (\function_exists('sodium_crypto_sign_verify_detached')) {
                $signIsOk = \sodium_crypto_sign_verify_detached($signatureBin, $hashHex, $keyPubBin);
            } else {
                throw new \Exception("No signature verification method. Enable sodium php-ext. or use polyfill 'composer require paragonie/sodium_compat'");
            }
            
            if (!$signIsOk) {
                throw new \Exception("Invalid signature");
            }
            $this->lastSuccessPubKeyBin = $keyPubBin;
        }

        $resultArr = [];
        $arr = \explode("\n", $this->hashSignedStr);
        foreach($arr as $st) {
            $i = \strpos($st, ':');
            if ($i) {
                $j = \strpos($st, ' ', $i + 2);
                if ($j) {
                    $fileShortName = \substr($st, 0, $i);
                    $fileHashHex = \substr($st, $i + 2, $j - $i - 2);
                    $resultArr[$leftPartOfKey . $fileShortName] = [$fileShortName, $fileHashHex, \substr($st, $j+1)];
                }
            }
        }

        return $resultArr;
    }

    public function loadHashSigArr(string $hashSigFileFull, $leftPartOfKey = null, bool $doNotVerifyHash = false, bool $doNotVerifySignature = false, array $pkgTrustedKeys = null): ?array {
        $hashSigFileFull = \strtr($hashSigFileFull, '\\', '/');
        if (\is_null($leftPartOfKey)) {
            $leftPartOfKey = \dirname($hashSigFileFull);
        }

        $hashSignedStr = $this->peekFromURLorFile($hashSigFileFull);

        if (!$hashSignedStr) {
            return null;
        }
        $hashSignedArr = $this->unpackHashSignedStr($hashSignedStr, $leftPartOfKey, $doNotVerifyHash, $doNotVerifySignature, $pkgTrustedKeys);
        if (!$hashSignedArr) {
            return null;
        }
        return $hashSignedArr;
    }
    
    public static function peekFromURLorFile(string $urlORfile, int $fileExpectedLen = null, int $fileOffset = 0): ?string {
        if (\strpos($urlORfile, '://')) {
            if (!$this->peekContext) {
                $this->peekContext = \stream_context_create([
                    "ssl" => [
                        "verify_peer" => false,
                        "verify_peer_name" => false,
                    ],
                ]);
            }
            $dataStr = @\file_get_contents($urlORfile, false, $this->peekContext, $fileOffset);
        } else {
            if (!\file_exists($urlORfile)) {
                return null;            
            }
            $dataStr = \file_get_contents($urlORfile, false, null, $fileOffset);
        }
        if (!\is_string($dataStr)) {
            return null;
        }
        return $dataStr;
    }
    
    // HashSig downloader below:
    public string $tempZipFile = '';

    public function __destruct() {
        $this->unlinkTempZipFile();
    }
    
    public function unlinkTempZipFile() {
        if ($this->tempZipFile && \file_exists($this->tempZipFile) && @\unlink($this->tempZipFile)) {
            $this->tempZipFile = '';
        }
    }

    public function getFilesByHashSig(
        string $hashSigFileFull,
        string $saveToDir = null,
        array $baseURLs = null,
        bool $doNotSaveFiles = false,
        bool $doNotOverWrite = false,
        bool $zipOnlyMode = false,
        array $onlyTheseFilesArr = null
    ) {
        // get $pkgTrustedKeys from URL (if specified by |pubkey|pubkey...)
        $palPos = \strpos($hashSigFileFull, '|');
        $sharPos = \strpos($hashSigFileFull, '#');
        if ($sharPos && $palPos && $sharPos < $palPos) {
            $palPos = $sharPos;
        }
        // get $onlyTheseFilesArr from URL (if specified by #file#file2#file3...)
        $sharPos = \strpos($hashSigFileFull, '#', $palPos ? $palPos + 1 : 0);
        if ($sharPos) {
            if (!$onlyTheseFilesArr) {
                // use $onlyTheseFilesArr unless specified otherwise
                $onlyTheseFilesArr = \explode('#', \substr($hashSigFileFull, $sharPos + 1));
            }
            $hashSigFileFull = \substr($hashSigFileFull, 0, $sharPos);
        }
        if ($palPos) {
            $pkgTrustedKeys = \explode('|', substr($hashSigFileFull, $palPos + 1));
            $hashSigFileFull = \substr($hashSigFileFull, 0, $palPos);
        } else {
            $pkgTrustedKeys = null;
        }
        if (\substr($hashSigFileFull, -4) === '.zip') {
            $zipMode = true;
            $zipData = $this->peekFromURLorFile($hashSigFileFull);
            if (!$zipData) {
                throw new \Exception("Can't read data from $hashSigFileFull");
            }
            $hashSigFileFull = \substr($hashSigFileFull, 0, -4);
        } else {
            if ($zipOnlyMode) {
                throw new \Exception("Zip-only sources accepted");
            }
            $zipMode = false;
        }
        
        $baseHSFile = \basename($hashSigFileFull);
        
        if ($zipMode) {
            $this->tempZipFile = \tempnam(\sys_get_temp_dir(), $baseHSFile);
            $wb = \file_put_contents($this->tempZipFile, $zipData);
            if (!$wb) {
                throw new \Exception("Can't write temporary downloaded zip-archive data to " . $this->tempZipFile);
            }
        }
        
        // check-prepare saveToDir
        $chkSaveToDir = $saveToDir ? $saveToDir : $this->srcPath;
        if (!$doNotSaveFiles && $chkSaveToDir && !\is_dir($chkSaveToDir) && !\mkdir($chkSaveToDir, 0777, true)) {
            throw new \Exception("Not found and can't create target dir: $chkSaveToDir");
        }
        if ($saveToDir) {
            $this->setDir($saveToDir, $baseHSFile);
        }
        $saveToDir = $this->srcPath;
        $targetHSFile = $this->hashSigFile;

        if ($zipMode) {
            $baseURLs = ['zip://' . $this->tempZipFile . '#'];
            $hashSigFileFull = $baseURLs[0] . $baseHSFile;
            // check hashSigFileFull
            if (empty(\file_get_contents($hashSigFileFull))) {
                $foundHSFile = '';
                $zip = new ZipArchive();
                if ($zip->open($this->tempZipFile) !== true) {
                    throw new \Exception("Can't open temporary zip-archive:" . $this->tempZipFile);
                }
                $listZipArr = [];
                $allInDir =  null;
                for ($n = 0; $n < $zip->numFiles; $n++) {
                    $entry = $zip->getNameIndex($n);
                    $i = \strrpos($entry, '/');
                    $subDir1 = $i ? \substr($entry, 0, $i + 1) : '';
                    if (\substr($entry, -1) === '/') {
                        continue;
                    }
                    if (\is_null($allInDir)) {
                        $allInDir = $subDir1;
                    } elseif ($allInDir && ($allInDir !== \substr($subDir1, 0, \strlen($allInDir)))) {
                        $allInDir = '';
                    }
                    if (\substr($entry, -8) === '.hashsig') {
                        $baseURLs[0] .= $subDir1;
                        $foundHSFile = $i ? \substr($entry, $i + 1) : $entry;
                        break;
                    }
                    $listZipArr[] = $entry;
                }
                $hashSigFileFull = $baseURLs[0];
                if (empty($foundHSFile)) {
                    if ($allInDir) {
                        $l = \strlen($allInDir);
                        foreach($listZipArr as $n => $shortName) {
                            $listZipArr[$n] = \substr($shortName, $l);
                        }
                        $baseURLs[0] .= $allInDir;
                    }
                    $baseHSFile = 'autoindex.hashsig';
                    $hashSigStr = "hashsig: list\n" . \implode("\n", $listZipArr) . "\n";
                    $zip->addFile($zip->addFromString($baseHSFile, $hashSigStr));
                }
                $hashSigFileFull .= $baseHSFile;
                $zip->close();
                if ($baseHSFile) {
                    $this->setDir($saveToDir, $baseHSFile);
                }
            }
        } else {
            if (\is_null($baseURLs)) {
                $baseURLs = [\dirname($hashSigFileFull) . '/'];
            }
        }

        $this->hashSignedArr = $this->loadHashSigArr($hashSigFileFull, '', false, false, $pkgTrustedKeys);
        if (!$this->hashSignedArr) {
            throw new \Exception("Can't load hashSig file from $hashSigFileFull");
        }
        
        // prepare $onlyTheseFilesArr
        if ($onlyTheseFilesArr) {
            $masksArr = [];
            if (\is_string(\reset($onlyTheseFilesArr))) {
                $onlyTheseFilesArr = \array_flip($onlyTheseFilesArr);
                foreach($onlyTheseFilesArr as $k => $v) {
                    if (!\is_numeric($v)) {
                        throw new \Exception("Bad array format onlyTheseFilesArr: '$v'");
                    }
                    if (false !== \strpos($k, '?') || false !== \strpos($k, '*')) {
                        $masksArr[] = $k;
                        $v = [];
                    } else {
                        $v = false;
                    }
                    $onlyTheseFilesArr[$k] = $v;
                }
            }
        }
        
        $successArr = [];
        $errorsArr = [];
        $errMsgArr = [];
        
        foreach($this->hashSignedArr as $shortName => $fileHashLenArr) {
            if ($onlyTheseFilesArr) {
                if (\array_key_exists($shortName, $onlyTheseFilesArr)) {
                    $onlyTheseFilesArr[$shortName] = true;
                } elseif (!$masksArr)  {
                    continue;
                } else {
                    $matched = false;
                    foreach($masksArr as $mask) {
                        if (\fnmatch($mask, $shortName)) {
                            $onlyTheseFilesArr[$mask][] = $shortName;
                            $matched = true;
                            break;
                        }
                    }
                    if (!$matched) {
                        continue;
                    }
                }
            }
            $fileData = null;
            $fileHashHex = $fileHashLenArr[1];
            $fileExpectedLen = $fileHashLenArr[2];
            foreach($baseURLs as $currURL) {
                $fileURL = $currURL . $shortName;
                $fileData = $this->peekFromURLorFile($fileURL, $fileExpectedLen);
                if (!\is_null($fileData)) {
                    if (!$fileHashHex) {
                        break;
                    }
                    $chkHashHex = \hash($this->hashAlgName, $fileData);
                    if ($chkHashHex !== $fileHashHex && false !== \strpos($fileData, "\r")) {
                        // try set EOL to canonical
                        $fileData = \strtr($fileData, ["\r" => '']);
                        $chkHashHex = \hash($this->hashAlgName, $fileData);
                    }
                    if ($chkHashHex === $fileHashHex) {
                        break;
                    }
                    $errMsgArr[] = "Different hash in $fileURL";
                    $fileData = null;
                }
            }
            
            if (\is_null($fileData)) {
                $errorsArr[] = $shortName;
            } else {
                $targetFileName = $saveToDir . '/' . $shortName;
                if (!$doNotSaveFiles && $saveToDir) {
                    if (!$doNotOverWrite || !($is_file = \is_file($targetFileName))) {
                        if (false !== \strpos($shortName, '/')) {
                            $toDir = \dirname($targetFileName);
                            if (!\is_dir($toDir) && !\mkdir($toDir, 0777, true)) {
                                throw new \Exception("Can't write to file: $targetFileName");
                            }
                        }
                        if ($this->writeLogObj) {
                            $this->writeLogObj->logWriteByObj($targetFileName, $is_file ? 1 : 0, $fileHashHex);
                        }
                        $wb = \file_put_contents($targetFileName, $fileData);
                        $fileData = $targetFileName;
                    }
                }
                
                $successArr[$shortName] = $doNotSaveFiles ? $fileData : $targetFileName;
            }
        }
        
        $this->unlinkTempZipFile();
        
        return \compact('successArr', 'errorsArr', 'errMsgArr', 'onlyTheseFilesArr');
    }
}