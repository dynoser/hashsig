<?php
namespace dynoser\hashsig;

use dynoser\walkdir\WalkDir;

use \ZipArchive;

class HashSigCreater extends HashSigBase {
    
    public static $dontConvertEOLextArr = ',exe,jpg,jpeg,png,gif,ico,bin';
    
    public function __construct($ownSignerObj = null) {
        if (\is_string(self::$dontConvertEOLextArr)) {
            self::$dontConvertEOLextArr = \array_flip(\explode(',', self::$dontConvertEOLextArr));
        }
        $this->setOwnSignerObj($ownSignerObj);
    }
    
    public function makeIndexHashSignedZip(
        array $extArr = ['*'],
        array $excludePatterns = [],
        int $maxFilesCnt = 100,
        bool $getHidden = false,
        int $maxSizeBytes = 1024 * 1024  
    ) {
        $filesHashLenArr = $this->makeIndexHashSignedFile(
            $extArr,
            $excludePatterns,
            $maxFilesCnt,
            $getHidden,
            $maxSizeBytes      
        );
        if (!\is_array($filesHashLenArr)) {
            throw new \Exception("Unexpected type of resuls, code error");
        }
        
        $zipFileName = $this->hashSigFile . '.zip';
        $filesHashLenArr[$this->hashSigFile] = true;
        $result = self::packToZip($zipFileName, $this->srcPath, $filesHashLenArr);
        return $result;
    }
    
    public function makeIndexHashSignedFile(
        array $extArr = ['*'],
        array $excludePatterns = [],
        int $maxFilesCnt = 100,
        bool $getHidden = false,
        int $maxSizeBytes = 1024 * 1024
    ) {
        $hashSigFile = $this->hashSigFile;
        if (!$hashSigFile) {
            throw new \Exception("HashSig file must be set by ->setDir");
        }
        $targetAlreadyExist = \is_file($hashSigFile);

        $expectedIndexFile = '/' . self::HASHSIG_FILE_INDEX . self::HASHSIG_FILE_EXT;
        $isIndex = \substr($hashSigFile, -\strlen($expectedIndexFile)) === $expectedIndexFile;
        if ($isIndex || !$targetAlreadyExist) {
            $filesHashLenArr = $this->getFilesFromSrcPath(
                $extArr,
                $excludePatterns,
                $maxFilesCnt,
                $getHidden,
                $maxSizeBytes
            );    
        }
        if (!$isIndex && $targetAlreadyExist) {
            $filesHashLenArr = $this->loadHashSigArr($hashSigFile, $this->srcPath . '/', true, true);
        }

        $result = $this->writeHashSigFile($filesHashLenArr);
        if (!\is_string($result)) {
            throw new \Exception("Unexpected result, code error");
        }

        return $filesHashLenArr;
    }

    public function getFilesFromSrcPath(
        array $extArr = ['*'],
        array $excludePatterns = [],
        int $maxFilesCnt = 100,
        bool $getHidden = false,
        int $maxSizeBytes = 1024 * 1024
    ) {
        $excludePatterns[] = '*' . self::HASHSIG_FILE_EXT;
        $excludePatterns[] = '*' . self::HASHSIG_FILE_EXT . '.zip';
        return self::getFilesFromPath(
            $this->srcPath,
            $this->hashAlgName,
            $extArr,
            $excludePatterns,
            $maxFilesCnt,
            $getHidden,
            $maxSizeBytes
        );
    }

    public static function getFilesFromPath(
        string $srcPath,
        string $hashAlgName,
        array $extArr = ['*'],
        array $excludePatterns = [],
        int $maxFilesCnt = 100,
        bool $getHidden = false,
        int $maxSizeBytes = 1024 * 1024
    ) {
        $filesHashLenArr = [];
        $filesCnt = 0;
        $l = \strlen($srcPath);
        
        $maxDepth = ($maxFilesCnt > 99) ? 99: $maxFilesCnt;
        
        $filesArr = WalkDir::getFilesArr(
            $srcPath,
            false,// $setKeys
            $extArr,
            $excludePatterns,
            $getHidden,
            true,
            $maxDepth
        );
        
        $filesCnt = 0;
        foreach($filesArr as $fullName => $fileSize) {
            if ($fileSize <= $maxSizeBytes) {
                $filesCnt++;
            }
        }
        
        if ($filesCnt > $maxFilesCnt) {
            throw new \Exception("Too many files: $filesCnt maxFilesCnt=$maxFilesCnt");
        }

        foreach($filesArr as $fullName => $fileSize) {
            if (!$fileSize || $fileSize > $maxSizeBytes) {
                continue;
            }

            $fileData = \file_get_contents($fullName);
            if (!\is_string($fileData)) {
                continue;
            }

            $i = \strrpos($fullName, '.');            
            if (false !== \strpos($fileData, "\r") && false !== $i) {
                $ext = \strtolower(\substr($fullName, $i + 1));
                if (empty(self::$dontConvertEOLextArr[$ext])) {
                    $fileData = \strtr($fileData, ["\r" => '']);
                }
            }
            $hashHex = \hash($hashAlgName, $fileData);

            if ($hashHex) {
                $shortPathName = \substr($fullName, $l + 1);
                if (false !== \strpos($shortPathName, ':')) {
                    throw new \Exception("Illegal character ':' in file name $shortPathName");
                }
                $hashSigRow = $shortPathName . ': ' . $hashHex . ' ' . $fileSize;
                $filesHashLenArr[$fullName] = $hashSigRow;
            } else {
                throw new \Exception("Hash error: $hashAlgName");
            }
        }
        return $filesHashLenArr;
    }
    
    public function makeHashSignedStr(array $filesHashLenArr): string {
        if (!$this->canSign) {
            throw new \Exception("KeySignerObj->can_sign=true required");
        }
        $pubKeyBin = $this->ownPubKeyBin;
        if (!\is_string($pubKeyBin) || \strlen($pubKeyBin) < 32) {
            throw new \Exception("bad public Key");
        }
        $pubKeyB64 = \base64_encode($pubKeyBin);

        $filesCnt = 0;
        $sumArr = [];
        foreach($filesHashLenArr as $fileName => $fileHashLen) {
            if (\is_array($fileHashLen)) {
                $fileHashLen = $fileHashLen[0] . ': ' . $fileHashLen[1] . ' ' . $fileHashLen[2];
            }
            $sumArr[] = $fileHashLen;
            $filesCnt++;
        }
        $sumSt = \implode("\n", $sumArr);
        
        $sumHashHex = \hash($this->hashAlgName, $sumSt);
        $signatureBin = $this->ownSignerObj->signIt($sumHashHex);
        if (!\is_string($signatureBin) || \strlen($signatureBin) < 64) {
            throw new \Exception("Signature error");
        }
        $signatureB64 = \base64_encode($signatureBin);

        $signStr = "hashsig: $sumHashHex ~ filescnt: $filesCnt ~ hashalg: " . $this->hashAlgName . ' ~ signalg: ed25519 ~ pubkey: ' . $pubKeyB64 . ' ~ signature: ' . $signatureB64;
        
        return $signStr . "\n" . $sumSt . "\n";
    }

    public function writeHashSigFile(
        array $filesHashLenArr,
        string $hashSigFileFull = null
    ): string {
        if (!$hashSigFileFull) {
            $hashSigFileFull = $this->hashSigFile;
            if (!$hashSigFileFull) {
                throw new \Exception("hashSig file not set, please use setDir before");
            }
        }
        
        $diffArr = $this->compareHashSigFiles($hashSigFileFull, $filesHashLenArr, false);
        if ($diffArr) {
            throw new \Exception("Files do not match the provided array");
        }
        $hashSignedStr = $this->makeHashSignedStr($filesHashLenArr);
        if (!$hashSignedStr) {
            throw new \Exception("Error pack hashSignedStr");
        }
        $wb = \file_put_contents($hashSigFileFull, $hashSignedStr);
        if (!$wb) {
            throw new \Exception("Can't write hashSigFile: $hashSigFileFull");
        }
        return $hashSignedStr;
    }
    
    public function compareHashSigFiles(
        string $hashSigFileFull = null,
        array $hashSignedArr = [],
        bool $updateMode = false,
        array $addFiles = [],
        array $removeFiles = []
    ): ?array {
        if (!$hashSigFileFull) {
            $hashSigFileFull = $this->hashSigFile;
            if (!$hashSigFileFull) {
                throw new \Exception("hashSig file not set, please use setDir before");
            }
        }

        $hashSigFileFull = \strtr($hashSigFileFull, '\\', '/');
        $leftPartOfKey = \dirname($hashSigFileFull) . '/';
        $lpl = \strlen($leftPartOfKey);

        if (!$hashSignedArr) {
            $oldHashSignedStr = \file_get_contents($hashSigFileFull);
            if (!$oldHashSignedStr) {
                return null;
            }
            $hashSignedArr = $this->unpackHashSignedStr($oldHashSignedStr, $leftPartOfKey, true, true);
            if (!$hashSignedArr) {
                return null;
            }
        }

        $hashAlgName = $this->hashAlgName;
        $hashHexLen = $this->hashHexLen;

        $changedFilesArr = [];

        foreach($addFiles as $fileFull) {
            $fileFull = \strtr($fileFull, '\\', '/');
            if (\substr($fileFull, 0, \strlen($leftPartOfKey) !== $leftPartOfKey)) {
                $fileFull = $leftPartOfKey . '/' . $fileFull; 
            }
            if (!\file_exists($fileFull)) {
                throw new \Exception("Can't add file $fileFull, not found");
            }
            $hashSignedArr[$fileFull] = '';
        }

        foreach($removeFiles as $fileFull) {
            $fileFull = \strtr($fileFull, '\\', '/');
            if (!\array_key_exists($fileFull, $hashSignedArr)) {
                if (\substr($fileFull, 0, \strlen($leftPartOfKey) !== $leftPartOfKey)) {
                    $fileFull = $leftPartOfKey . '/' . $fileFull; 
                }
            }
            if (\array_key_exists($fileFull, $hashSignedArr)) {
                $changedFilesArr[$fileFull] = false;
                unset($hashSignedArr[$fileFull]);
            }
        }

        foreach($hashSignedArr as $fileFull => $hashLenStr) {
            if (\file_exists($fileFull)) {
                $content = \file_get_contents($fileFull);
            } else {
                $fileFull = null;
            }
            if (!\is_string($content)) {
                $changedFilesArr[$fileFull] = false;
                continue;
            }
            foreach([\hash($hashAlgName, $content), ''] as $newHashHex) {
                if (!$newHashHex) {
                    if (false === \strpos($content, "\r")) {
                        break;
                    }
                    // try set EOL to canonical and check again
                    $content = \strtr($content, ["\r" => '']);
                    $newHashHex = \hash($hashAlgName, $content);
                }
                if (\is_array($hashLenStr)) {
                    $isEqual = $hashLenStr[1] === $newHashHex;
                } else {
                    $isEqual = (false !== \strpos($hashLenStr, $newHashHex));
                }
                if ($isEqual) {
                    break;
                }
            }
            if (!$isEqual) {
                $shortName = \substr($fileFull, $lpl);
                $newFileSize = \filesize($fileFull);
                $newHashLenStr = $shortName . ': ' . $newHashHex . ' ' . $newFileSize;
                $hashSignedArr[$fileFull] = $newHashLenStr;
                $changedFilesArr[$fileFull] = $newHashLenStr;
            }
        }
        
        if ($updateMode) {
            $newHashSignedStr = $this->makeHashSignedStr($hashSignedArr);
            $wb = \file_put_contents($hashSigFileFull, $newHashSignedStr);
            if (!$wb) {
                throw new \Exception("Error write file: $hashSigFileFull");
            }
        }

        return $changedFilesArr;
    }
    
    public static function packToZip(string $zipFileName, string $pathSrc, array $filesInKeysArr) {
        $zip = new ZipArchive();
        if ($zip->open($zipFileName, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
            return false;
        }
        $lp = \strlen($pathSrc);
        $createdSubDirs = [];
        foreach ($filesInKeysArr as $absORrelFilePath => $value) {
            if (\substr($absORrelFilePath, 0, $lp) === $pathSrc) {
                $relativeFilePath = \substr($absORrelFilePath, $lp + 1);
            } else {
                $relativeFilePath = $absORrelFilePath;
            }
            $sourceFilePath = $pathSrc . '/' . $relativeFilePath;

            $i = -1;
            while($i = \strpos($relativeFilePath, '/', $i + 1)) {
                $subDir = substr($relativeFilePath, 0, $i);
                if (empty($createdSubDirs[$subDir])) {
                     $zip->addEmptyDir($subDir);
                     $createdSubDirs[$subDir] = true;
                }
            }
            $zip->addFile($sourceFilePath, $relativeFilePath);
        }

        $zip->close();
        return true;
    }

    public static function unpackZip(string $zipFileName, string $extractPath) {
        $zip = new ZipArchive();
        if ($zip->open($zipFileName) !== true) {
            return false;
        }
        
        $rp = \realpath($extractPath);
        if (!$rp) {
            !\mkdir($extractPath, 0777, true);
            $rp = \realpath($extractPath);
        }
        if ($rp) {
            $extractPath = \strtr($rp, '\\', '/');
        } else {
            return false;
        }

        $createdSubDirs = [];

        for ($i = 0; $i < $zip->numFiles; $i++) {
            $fileInfo = $zip->statIndex($i);

            $entryName = \strtr($fileInfo['name'], '\\', '/');

            if (\strpos($entryName, '..') === false) {
                $targetPath = $extractPath . '/' . $entryName;

                if (\substr($entryName, -1) === '/') {
                    if (empty($createdSubDirs[$targetPath])) {
                        if (!\is_dir($targetPath) && !\mkdir($targetPath, 0777, true)) {
                            throw new \Exception("Can't create subdir: $targetPath");
                        }
                        $createdSubDirs[$targetPath] = true;
                    }
                } else {
                    $zip->extractTo($extractPath, $entryName);
                }
            }
        }

        $zip->close();
        return true;
    }
}
