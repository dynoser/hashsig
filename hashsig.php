<?php
namespace dynoser\hashsig;

use dynoser\hashsig\HashSigBase;
use dynoser\hashsig\HashSigCreater;
use dynoser\walkdir\WalkDir;

// default parameters for scan files:
$srcPath = \getcwd();
$hashSigName = '';
$hashAlgName = 'sha256';
$filePatterns = [];
$excludePatterns = [];
$maxFilesCnt = 100;
$getHidden = false;
$maxSizeBytes = 1024 * 1024;

// target mode parameters
$targetPath = null;
$checkMode = false;
$writeMode = false;

// keySigner parameters
$kobj = null;
$kopt = [
    'password' => \getenv('HASHSIG_PASSWORD'),
    'key' => \getenv('HASHSIG_KEYFILE')
];

// scan vendorDir
$vendorDir = null;
$myOwnDir = \strtr(__DIR__ , '\\', '/');
$nextChkDir = $myOwnDir . '/vendor';
do {
    $chkDir = $nextChkDir;
    if (\is_dir($chkDir)) {
        $vendorDir = $chkDir;
        break;
    }
    $nextChkDir = \dirname($chkDir, 2) . '/vendor';
} while (\strlen($nextChkDir) < \strlen($chkDir));

// def local files search function
$searchLocalFile = function($fileName, $vendorSubDir) use ($vendorDir, $myOwnDir) {
    foreach([$myOwnDir, $vendorDir . $vendorSubDir] as $chkDir) {
        $chkFile = $chkDir . $fileName;
        if (\is_file($chkFile)) {
            return $chkFile;
        }
    }
};

// HashSigBase class required local
if (!\class_exists('dynoser\\hashsig\\HashSigBase')) {
    $chkFile = $searchLocalFile("/src/HashSigBase.php", '/dynoser/hashsig/');
    if ($chkFile) {
        require_once $chkFile;
    }
    if (!\class_exists('dynoser\\hashsig\\HashSigBase')) {
        throw new \Exception("Class dynoser\\hashsig\\HashSigBase required before all, can't countinue");        
    }
}

// seach all required files local
$checkAndDown = function($tryDownload = true) use ($vendorDir, $searchLocalFile) {
    $needDownload = [];
    foreach([
        '/src/WalkDir.php' => ['/dynoser/walkdir', 'https://raw.githubusercontent.com/dynoser/WalkDir/main/src/walkdir.hashsig.zip', '/src'],
        '/src/KeySigner.php' => ['/dynoser/keysigner', 'https://raw.githubusercontent.com/dynoser/keysigner/main/src/keysigner.hashsig.zip', '/src'],
        '/src/HashSigCreater.php' => ['/dynoser/hashsig', 'https://raw.githubusercontent.com/dynoser/hashsig/main/hashsig.hashsig.zip', ''],
    ] as $fileName => $vendorArr) {
        $chkFile = $searchLocalFile($fileName, $vendorArr[0]);
        if (!$chkFile) {
            $needDownload[$fileName] = $vendorArr;
        }
    }

    if ($needDownload && $vendorDir && $tryDownload) {
        foreach($needDownload as $fileName => $vendorArr) {
            $hsObj = new HashSigBase();
            $res = $hsObj->getFilesByHashSig(
                $vendorArr[1],
                $vendorDir . $vendorArr[0] . $vendorArr[2], //$saveToDir
                null,  // $baseURLs
                false, // $doNotSaveFiles
                true,  // $doNotOverWrite
                true   // $zipOnlyMode
            );
        }
    }
    return $needDownload;
};

if ($checkAndDown()) {
    $needDownload = $checkAndDown(false);
    if ($needDownload) {
        echo "Not found and can't download it:";
        print_r($needDownload);
    }
}

$scanClassFileFn = function ($classFullName) use ($myOwnDir, $vendorDir) {
    static $nameSpacesArr = [];
    if (!$nameSpacesArr) {
        $nameSpacesArr = [
            'dynoser\\hashsig\\' => $myOwnDir . '/src/',
            'dynoser\\keysigner\\' => $vendorDir . '/dynoser/keysigner/src/',
            'dynoser\\walkdir\\' => $vendorDir . '/dynoser/walkdir/src/',
        ];
    }
    foreach($nameSpacesArr as $nameSpacePrefix => $srcDir) {
        if (\strncmp($nameSpacePrefix, $classFullName, \strlen($nameSpacePrefix)) !== 0) {
            continue;
        }
        $relativeClass = \substr($classFullName, \strlen($nameSpacePrefix));
        $file = $srcDir . \strtr($relativeClass, '\\', '/') . '.php';
        if (\file_exists($file)) {
            return $file;
        }
    }
};

if (!\class_exists('dynoser\\autoload\\AutoLoadSetup', false)) {
    if (empty($optionsArr['vendorautoload'])) {
        // set own autoloader for own classes
        \spl_autoload_register(function ($classFullName) use ($scanClassFileFn) {
            $file = $scanClassFileFn($classFullName);
            if ($file) {
                require_once $file;
            }
        });
    } else {
        if (!\class_exists('dynoser\\autoload\\AutoLoadSetup')) {
            foreach([
                \dirname($myOwnDir, 2) . '/vendor',
                $myOwnDir . '/vendor',
                $vendorDir,
            ] as $chkDir) {
                $chkFile = \trim($chkDir, '\\/') . '/autoload.php';
                if (\is_file($chkFile)) {
                    include_once $chkFile;
                    break;
                }
            }
        }
    }
}


// get options from command string (or from get-parameters)
$optionsArr = (function() {
    $optionsArr = [];
    if (!isset($GLOBALS['argv'])) {
        // could it be a web request?
        if (!isset($_SERVER['PHP_SELF'])) {
            // no known sources of arguments
            return [];
        }
        // assume this is a web request
        $argv = [$_SERVER['PHP_SELF']];
        if (!empty($_REQUEST)) {
            foreach($_REQUEST as $k => $v) {
                if ($v == 1 || $v === '') {
                    $argv[] = $k;
                } elseif (\substr($k, 0, 3) === 'arg') {
                    $argv[] = $v;
                }
            }
        }
        // set global $argv and $argc
        $GLOBALS['argv'] = $argv;
        $GLOBALS['argc'] = \count($argv);
        // show request
        header("Content-Type: text/plain");
        echo "Run " . \implode(' ', $argv) . "\n\n";
    }

    // check arguments in global $argv and $argc
    if (isset($GLOBALS['argv'])) {
        foreach($GLOBALS['argv'] as $k => $argStr) {
            $isOption = false;
            while(\substr($argStr, 0, 1) === '-') {
                $argStr = \substr($argStr, 1);
                $isOption = true;
            }
            if (!$isOption) {
                continue;
            }
            $i = \strpos($argStr, '=');
            if ($i) {
                $optName = \substr($argStr, 0, $i);
                $optValue = \substr($argStr, $i + 1);
            } else {
                $optName = $argStr;
                $optValue = true;
            }
            $optName = \strtolower($optName);
            if (\array_key_exists($optName, $optionsArr)) {
                if (\is_string($optionsArr[$optName])) {
                    $optionsArr[$optName] = [$optionsArr[$optName], $optValue];
                } else {
                    $optionsArr[$optName][] = $optValue;
                }
            } else {
                $optionsArr[$optName] = $optValue;
            }
            unset($GLOBALS['argv'][$k]);
        }
    }
    return $optionsArr;
})();


$configExt = HashSigBase::HASHSIG_FILE_EXT . '.json';


$url = '';

if (!empty($GLOBALS['argv'][1])) {
    $par = $GLOBALS['argv'][1];
    if (\filter_var($par, \FILTER_VALIDATE_URL)) {
        $url = $par;
    } elseif (\is_dir($par)) {
        $srcPath = $par;
    } elseif (\is_file($par)) {
        $chkName = \basename($par);
        $i = \strpos($chkName, HashSigBase::HASHSIG_FILE_EXT);
        if (false === $i) {
            throw new \Exception("File must have .hashsig based name");
        } else {
            $hashSigName = \substr($chkName, 0, $i);
        }
        $srcPath = \dirname($par);
    } else {
        throw new \Exception("Understand");
    }
    if ($srcPath) {
        $srcPath = \realpath($srcPath);
        if ($srcPath) {
            $srcPath = \strtr($srcPath, '\\', '/');
        }
    }
}


$rewriteOptions = [];

foreach($optionsArr as $optName => $optValue) {
    switch($optName) {
    case 'url':
    case 'from':
    case 'fromurl':
        if (\filter_var($optValue, \FILTER_VALIDATE_URL)) {
            $url = $optValue;
        } else {
            throw new \Exception("Invalid url=$optValue");
        }
        break;
    case 'pathfrom':
        if (!\is_string($optValue)) {
            throw new \Exception("Only 1 $optName-parameter supported");
        }
        $itsFile = \is_file($optValue);
        $itsDir  = \is_dir($optValue);
        $hashSigConfig = ($itsFile && (\substr($optValue, -\strlen($configExt)) === $configExt)) ? $optValue : null;
        $optValue = $itsDir ? $optValue : \dirname($optValue);
        $srcPath = \strtr($optValue, '\\', '/');
        if (!$hashSigConfig) {
            if (($itsFile || $itsDir) && !empty($optionsArr['autonamebypath'])) {
                $hashSigConfig = $srcPath . '/temp' . $configExt;
            } else {
                while (\strrpos($srcPath, '/')) {
                    $hashSigFilesArr = WalkDir::getFilesArr($srcPath, false, '*' . $configExt);
                    if (!empty($hashSigFilesArr)) {
                        echo "Found configurations:\n";
                        foreach($hashSigFilesArr as $n => $hashSigConfig) {
                            echo " $hashSigConfig\n";
                            if ($n && empty($optionsArr['getfirstconfig'])) {
                                throw new \Exception("You may use option --getfirstconfig");
                            }
                        }
                        break;
                    }
                    $srcPath = \dirname($srcPath);
                }
            }
        }
        if (!$hashSigConfig) {
            throw new \Exception("Can't autodetect srcPath by pathfrom=$optValue");
        }
        $hashSigName = \substr(\basename($hashSigConfig), 0, -\strlen($configExt));
        $optValue = \dirname($hashSigConfig);
    case 'path':
    case 'srcpath':
        if (\is_string($optValue)) {
            $srcPath = \realpath($optValue);
            if ($srcPath) {
                $srcPath = \strtr($srcPath, '\\', '/');
            } else {
                throw new \Exception("Not found source path=$optValue\n");
            }
        } else {
            throw new \Exception("Only 1 path-parameter supported");
        }
        break;
    case 'target':
        if (\is_string($optValue)) {
            $targetPath = \realpath($optValue);
            if (!$targetPath) {
                $targetPath = \realpath(\dirname($optValue));
                if (!$targetPath || !\is_dir($targetPath)) {
                    throw new \Exception("Can't create target dir more than 1 level deep: $optValue");
                }
                $targetPath .= '/'. basename($optValue);
            }
            $targetPath = \strtr($targetPath, '\\', '/');
        } else {
            throw new \Exception("Only 1 'target' parameter supported");
        }
        break;
    case 'ex':
    case 'exclude':
        if (\is_string($optValue)) {
            $excludePatterns[] = $optValue;
        } elseif (\is_array($optValue)) {
            $excludePatterns += $optValue;
        }
        $rewriteOptions['excludePatterns'] = $excludePatterns;
        break;
    case 'pattern':
        $filePatterns[] = $optValue;
        $rewriteOptions['filePatterns'] = $filePatterns;
        break;
    case 'maxfiles':
        $maxFilesCnt = $optValue;
        $rewriteOptions['maxFilesCnt'] = $maxFilesCnt;
        break;
    case 'maxsize':
    case 'maxsizebytes':
            $maxSizeBytes = (int)$optValue;
            if ($maxSizeBytes) {
                $rewriteOptions['maxSizeBytes'] = $maxSizeBytes;
            }
        break;
    case 'autonamebypath':
        $tmpSrcPath = $srcPath;
        do {
            $optValue = \basename($tmpSrcPath);
            $tmpSrcPath = \dirname($tmpSrcPath);
        } while ($optValue === 'src');
    case 'name':
        if (false !== \strpos($optValue, '.')) {
            throw new \Exception("Can't use names with dots");
        }
        $hashSigName = $optValue;
        break;
    case 'key':
    case 'ppk':
    case 'keyfile':
        $kopt['key'] = $optValue;
        break;
    case 'keygen':
    case 'genkey':
        $kopt['genkey'] = $optValue;
        break;
    case 'password':
        $kopt['password'] = $optValue;
        break;
    case 'keyrewrite':
        $kopt['keyrewrite'] = !empty($optValue);
        break;
    case 'rewrite':
        $removeBefore = true;
    case 'write':
        $writeMode = empty($checkMode) && empty($optionsArr['check']) && !empty($optValue);
        break;
    case 'check':
        $checkMode = true;
        $writeMode = false;
        break;
    case 'hash':
    case 'hashalg':
        $hashAlgName = $optValue;
        break;
    default:
        echo "Unknown option: $optName\n";
    }
}

if (!$filePatterns) {
    $filePatterns = ['*'];
}

// name calculation
if (!\array_key_exists('name', $optionsArr) && !$hashSigName && $srcPath && \is_dir($srcPath)) {
    // name not specified in options, try search options in .hashsig.json files
    $mask = $srcPath . '/*' . $configExt;
    $namesArr = \glob($mask);
    foreach($namesArr as $n => $fullName) {
        $shortOptFile = \basename($fullName);
        $namesArr[$n] = \substr($shortOptFile, 0, -\strlen($configExt));
    }
    if ($namesArr) {
        $cnt = \count($namesArr);
        if ($cnt > 1) {
            echo "Found $cnt names, must specified one of:\n";
            foreach($namesArr as $oneName) {
                echo " --name=$oneName\n";
            }
            throw new \Exception("Can't autodetect --name");
        }
        $hashSigName = \reset($namesArr);
        if ($hashSigName) {
            echo "Option autodetected: --name=$hashSigName \n";
        } else {
            echo "(old options loaded)\n";
        }
    }
    
}

try {
    if ($kopt['key']) {
        $keyORfile = $kopt['key'] ?? null;
        $isFile = \is_file($keyORfile);
        $password = $kopt['password'] ? $kopt['password'] : false;
        if (empty($kopt['genkey'])) {
            if ($isFile) {
                $keystr = \file_get_contents($keyORfile);
            } else {
                throw new \Exception("Key must be in file\n");
                //$keystr = $keyORfile;
            }
            $kobj = new \dynoser\keysigner\KeySigner($keystr, $password);
        } else {
            if ($isFile && empty($kopt['keyrewrite'])) {
                throw new \Exception("Key-file already exist, use option --keyrewrite or remove this file manually: $keyORfile\n");
            }
            $fileForKeySave = (\is_string($keyORfile) && strlen($keyORfile) > 3) ? $keyORfile : null;
            if ($fileForKeySave) {
                $dirForKeySave = \dirname($keyORfile);
                $rp = \realpath($dirForKeySave);
                if (!$rp) {
                    throw new \Exception("Directory for storage key NOT EXIST: $dirForKeySave \n");
                }
                if (!\is_writable($dirForKeySave)) {
                    throw new \Exception("Directory for storage key NOT WRITABLE: $dirForKeySave \n");
                }
            }
            $kobj = new \dynoser\keysigner\KeySigner();
            $kobj->init();
            $keystr = $kobj->dumpKeyPair($password, false, false);
            echo "Private key: $keystr \n";
            if ($fileForKeySave) {
                $wb = \file_put_contents($fileForKeySave, $keystr);
                if (!$wb) {
                    throw new \Exception("Error write key data, file=$fileForKeySave \n");
                }
                echo "Key saved to file: $fileForKeySave \n";
                if ($password) {
                    echo "(Encrypted by specified passrwod, --password option required to use this file)\n";
                } else {
                    echo "(Not encrypted, no password required to use this key-file)\n";
                }
            }
        }
    }    
    if ($kobj) {
        echo "My public key is: " . \base64_encode($kobj->pub_key) . "\n";
    }
    $hsObj = new HashSigCreater($kobj);
    $hsObj->setDir($srcPath, $hashSigName);
    if ($url) {
        $writeMode = false;
        $hashSigFileFull = $url;
    } else {
        $hashSigFileFull = $hsObj->hashSigFile;
    }
    if (!$checkMode && !$url && !\is_file($hsObj->hashSigFile)) {
        $writeMode = true;
    }
    if (!$writeMode) {
        if ($checkMode) {
            echo "Checking: $hashSigFileFull\n";
        }
//            $chkHSobj = new HashSigBase();
        $chkHSobj = $hsObj;
        $doNotSaveFile = empty($targetPath) || $checkMode;
        if ($doNotSaveFile) {
            $targetPath = null;
        } else {
            echo "Target path: $targetPath\n";
            if (!\is_dir($targetPath) && !\mkdir($targetPath)) {
                throw new Exception("Can't create target path=$targetPath");
            }
        }
        $ret = $chkHSobj->getFilesByHashSig(
            $hashSigFileFull,
            $targetPath,
            null,
            $doNotSaveFile
        );
        $filesArr = [];
        if (empty($ret['successArr'])) {
            echo "No success results\n";
        } else {
            echo "Contains success results, public key=" . \base64_encode($chkHSobj->lastSuccessPubKeyHex) . "\n";
            if ($kobj && $kobj->pub_key === $chkHSobj->lastSuccessPubKeyHex) {
                echo " (it is my own pubkey)\n";
            } else {
                echo " !!! FOREING PUBLIC KEY !!!\n";
            }
            if ($doNotSaveFile) {
                foreach($ret['successArr'] as $fileShortName => $fileData) {
                    $filesArr[$hsObj->srcPath . '/' . $fileShortName] = [$fileShortName, \hash($hashAlgName, $fileData), \strlen($fileData)];
                }
            } else {
                foreach($ret['successArr'] as $fileShortName => $fileName) {
                    $filesArr[$hsObj->srcPath . '/' . $fileShortName] = [$fileName, '', 1];
                }
            }
        }
        if (!empty($ret['errorsArr'])) {
            echo "Error results:\n";
            print_r($ret['errorsArr']);
        }
        if (!empty($err['errMsgArr'])) {
            echo "Error messages:\n";
            print_r($ret['errMsgArr']);
        }
    } else {
        echo "Write mode ON\n";
        if (!empty($removeBefore) && \is_file($hashSigFileFull)) {
            echo " Remove old: $hashSigFileFull ... ";
            if (\unlink($hashSigFileFull)) {
                echo "Success \n";
            } else {
                echo "ERROR \n";
            }
        }
        $filesArr = $hsObj->makeIndexHashSignedZip(
            $filePatterns,
            $excludePatterns,
            $maxFilesCnt,
            $getHidden,
            $maxSizeBytes,
            $rewriteOptions
        );
    }
} catch (\Throwable $e) {
    $error = $e->getMessage();
    die("ERROR: $error \n BREAK\n");
}

if (\is_array($filesArr)) {
    $filesCnt = \count($filesArr);
    if ($filesCnt) {
        echo "Files in $srcPath :\n";
        foreach($filesArr as $fileFullName => $fileHashLen) {
            if (\is_string($fileHashLen)) {
                $shortFileName = substr($fileHashLen, 0, \strpos($fileHashLen, ':'));
            } elseif (\is_array($fileHashLen)) {
                $shortFileName = $fileHashLen[0];
            } else {
                $shortFileName = \basename($fileFullName);
            }
            echo " $shortFileName\n";
        }
        echo "Total $filesCnt files\n";
        if (WalkDir::$fileCountThreshold && (WalkDir::$fileCountTotal > WalkDir::$fileCountThreshold)) {
            echo "--- BROKEN BY MAXFILES: " . WalkDir::$fileCountThreshold . " ---\n";
        }
        if ($writeMode) {
            $zipFile = $hashSigFileFull . '.zip';
            if (\is_file($zipFile)) {
                echo "Zipped package: $zipFile\n";
            }
        }
    } else {
        echo "Not found files with current criterias\n";
    }
}
