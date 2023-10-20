<?php
namespace dynoser\hashsig;

class HashSig extends HashSigBase {
    public string $tempZipFile = '';
    
    public function __construct($ownSignerObj = null) {
        $this->setOwnSignerObj($ownSignerObj);
    }
    
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
        bool $doNotOverWrite = false
    ) {
        if (\substr($hashSigFileFull, -4) === '.zip') {
            $zipMode = true;
            $zipData = $this->peekFromURLorFile($hashSigFileFull);
            if (!$zipData) {
                throw new \Exception("Can't read data from $hashSigFileFull");
            }
            $hashSigFileFull = \substr($hashSigFileFull, 0, -4);
        } else {
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
        if (!$doNotSaveFiles && !\is_dir($chkSaveToDir) && !\mkdir($chkSaveToDir)) {
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
        } else {
            if (\is_null($baseURLs)) {
                $baseURLs = [\dirname($hashSigFileFull) . '/'];
            }
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
                    if (!$doNotOverWrite || !\is_file($targetFileName)) {
                        if (false !== \strpos($shortName, '/')) {
                            $toDir = \dirname($targetFileName);
                            if (!\is_dir($toDir) && !\mkdir($toDir, 0777, true)) {
                                throw new \Exception("Can't write to file: $targetFileName");
                            }
                        }
                        $wb = \file_put_contents($targetFileName, $fileData);
                        $fileData = $targetFileName;
                    }
                }
                
                $successArr[$shortName] = $fileData;
            }
        }
        
        $this->unlinkTempZipFile();

        return \compact('successArr', 'errorsArr', 'errMsgArr');
    }
}
