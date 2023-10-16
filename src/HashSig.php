<?php
namespace dynoser\hashsig;

use dynoser\walkdir\WalkDir;

class HashSig extends HashSigBase {
    public function __construct($ownSignerObj = null) {
        $this->setOwnSignerObj($ownSignerObj);
    }

    public function getFilesByHashSig(
        string $hashSigFileFull,
        string $saveToDir = null,
        array $baseURLs = null,
        bool $doNotSaveFiles = false
    ) {
        $baseHSFile = \basename($hashSigFileFull);
        
        // check-prepare saveToDir
        $chkSaveToDir = $saveToDir ? $saveToDir : $this->srcPath;
        if (!\is_dir($chkSaveToDir) && !\mkdir($chkSaveToDir)) {
            throw new \Exception("Not found and can't create target dir: $chkSaveToDir");
        }
        if ($saveToDir) {
            $this->setDir($saveToDir, $baseHSFile);
        }
        $saveToDir = $this->srcPath;
        $targetHSFile = $this->hashSigFile;

        if (\is_null($baseURLs)) {
            $baseURLs = [\dirname($hashSigFileFull) .'/'];
        }

        $hashSignedArr = $this->loadHashSigArr($hashSigFileFull, '');
        if (!$hashSignedArr) {
            throw new \Exception("Can't load hashSig file from $hashSigFileFull");
        }
        
        $successArr = [];
        $errorsArr = [];
        $errMsgArr = [];
        
        foreach($hashSignedArr as $shortName => $fileHashLenArr) {
            $fileData = null;
            $fileHashHex = $fileHashLenArr[1];
            $fileExpectedLen = $fileHashLenArr[2];
            foreach($baseURLs as $currURL) {
                $fileURL = $currURL . $shortName;
                $fileData = $this->peekFromURLorFile($fileURL, $fileExpectedLen);
                if (!\is_null($fileData)) {
                    $chkHashHex = \hash($this->hashAlgName, $fileData);
                    if ($chkHashHex !== $fileHashHex && false !== \strpos($fileData, "\r")) {
                        // try set EOL to canonical
                        $fileData = \strtr($fileData, ["\r" => '']);
                        $chkHashHex = \hash($this->hashAlgName, $fileData);
                    }
                    if ($chkHashHex !== $fileHashHex) {
                        $errMsgArr[] = "Different hash in $fileURL";
                        $fileData = null;
                    } else {
                        break;
                    }
                }
            }
            
            if (\is_null($fileData)) {
                $errorsArr[] = $shortName;
            } else {
                if (!$doNotSaveFiles) {
                    $targetFileName = $saveToDir . '/' . $shortName;
                    if (false !== \strpos($shortName, '/')) {
                        $toDir = \dirname($targetFileName);
                        if (!\is_dir($toDir) && !\mkdir($toDir, 0777, true)) {
                            throw new \Exception("Can't write to file: $targetFileName");
                        }
                    }
                    $wb = \file_put_contents($targetFileName, $fileData);
                    $fileData = $targetFileName;
                }
                
                $successArr[$shortName] = $fileData;
            }
        }

        return \compact('successArr', 'errorsArr', 'errMsgArr');
    }
}
