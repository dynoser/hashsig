<?php
namespace dynoser\hashsig;

use dynoser\hashsig\HashSigBase;
use dynoser\hashsig\HashSigCreater;
use dynoser\walkdir\WalkDir;

use dynoser\autoload\AutoLoader;


$myOwnVersion = '1.0.3';
$myOwnName = "HashSig package manager version $myOwnVersion";

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

// nsmap options
if (!\defined('DYNO_NSMAP_URL') && empty($optionsArr['nonsmap'])) {
    $nsMapUrl = $optionsArr['nsmap'] ?? 'https://raw.githubusercontent.com/dynoser/nsmap/main/nsmap.hashsig.zip';
    define('DYNO_NSMAP_URL', $nsMapUrl);
    if (!\defined('DYNO_NSMAP_TIMEOUT')) {
        $nsMapTimeOut = $optionsArr['nsmaptimeout'] ?? 60;
        define('DYNO_NSMAP_TIMEOUT', $nsMapTimeOut);
    }
    echo ' (Using nsmap="' . \DYNO_NSMAP_URL . '" timeout=' . \DYNO_NSMAP_TIMEOUT . ")\n";
}

// scan vendorDir
$vendorDir = \defined('VENDOR_DIR') ? \constant('VENDOR_DIR') : null;
$myOwnDir = \strtr(__DIR__ , '\\', '/');
$nextChkDir = $myOwnDir . '/vendor';
do {
    $chkDir = $nextChkDir;
    if (\is_dir($chkDir)) {
        $vendorDir = $chkDir;
        break;
    }
    $nextChkDir = \rtrim(\dirname($chkDir, 2), '/\\') . '/vendor';
} while (\strlen($nextChkDir) < \strlen($chkDir));

if ($vendorDir) {
    // use vendor autoload if need
    if (!empty($optionsArr['a'])) {
        $chkFile = $vendorDir . '/autoload.php';
        if (\is_file($chkFile)) {
            echo " (Using autoloader=$chkFile )\n";
            require_once $chkFile;
        }
    }
    // check sodium polyfill
    if (!\function_exists('sodium_crypto_sign_verify_detached')) {
        $chkFile = $vendorDir . '/paragonie/sodium_compat/autoload.php';
        if (\is_file($chkFile)) {
            require_once $chkFile;
            echo " (polyfill 'paragonie/sodium_compat' is used)\n";
        }
    }
} else {
    // create vendor-dir if not found
    $vendorDir = $myOwnDir . '/vendor';
    if (!\mkdir($vendorDir)) {
        die ("Not found vendorDir and can't create '$vendorDir'");
    }
}

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
$hashSigBase = '/src/HashSigBase.php';
if (!\class_exists('dynoser\\hashsig\\HashSigBase')) {
    $chkFile = $searchLocalFile($hashSigBase, '/dynoser/hashsig/');
    if ($chkFile) {
        require_once $chkFile;
    }
    if (!\class_exists('dynoser\\hashsig\\HashSigBase')) {
        $chkDir = $myOwnDir . "/src";
        if (\is_dir($chkDir) || \mkdir($chkDir)) {
            $chkFile = $myOwnDir . $hashSigBase;
            $hashSigBaseURL = "https://raw.githubusercontent.com/dynoser/hashsig/main/src/HashSigBase.php";
            echo "Try auto-create $chkFile \n Download from: $hashSigBaseURL \n";
            if (copy($hashSigBaseURL, $chkFile)) {
                require_once $chkFile;
            }
        }
        if (!\class_exists('dynoser\\hashsig\\HashSigBase')) {
            throw new \Exception("Class dynoser\\hashsig\\HashSigBase required before all, can't countinue");
        }
    }
}

// seach all required files local
$checkAndDown = function($tryDownload, $pkgInstallArr) use ($vendorDir, $searchLocalFile) {
    $needDownload = [];

    foreach($pkgInstallArr as $fileName => $vendorArr) {
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

$ownHSCreaterFile = $myOwnDir . '/src/HashSigCreater.php';
$ownHSCreaterFile = \is_file($ownHSCreaterFile) ? $ownHSCreaterFile : '';
if ($ownHSCreaterFile && !\class_exists('dynoser\\hashsig\\HashSigCreater', false)) {
    echo " (Using $ownHSCreaterFile)\n";
    require_once $ownHSCreaterFile;
}

$pkgInstallArr = [
    '/src/WalkDir.php' => ['/dynoser/walkdir', 'https://raw.githubusercontent.com/dynoser/WalkDir/main/src/walkdir.hashsig.zip', '/src'],
    '/src/KeySigner.php' => ['/dynoser/keysigner', 'https://raw.githubusercontent.com/dynoser/keysigner/main/src/keysigner.hashsig.zip', '/src'],
];
if (!$ownHSCreaterFile) {
    $pkgInstallArr += [
    '/src/HashSigCreater.php' => ['/dynoser/hashsig', 'https://raw.githubusercontent.com/dynoser/hashsig/main/hashsig.hashsig.zip', ''],
    ];
}
if (!$ownHSCreaterFile || !empty($optionsArr['install'])) {
    $pkgInstallArr += [
    '/src/AutoLoader.php' => ['/dynoser/autoload', 'https://raw.githubusercontent.com/dynoser/autoload/main/autoload.hashsig.zip', ''],
    ];
}
if ($checkAndDown(true, $pkgInstallArr)) {
    $needDownload = $checkAndDown(false, $pkgInstallArr);
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
    if (!\class_exists('dynoser\\autoload\\AutoLoadSetup')) {
        foreach(['/dynoser/autoload', ''] as $appendPath) {
            foreach([
                \dirname($myOwnDir, 2) . '/vendor' . $appendPath,
                $myOwnDir . '/vendor' . $appendPath,
                $vendorDir . $appendPath,
            ] as $chkDir) {
                $chkFile = \trim($chkDir, '\\/') . '/autoload.php';
                if (\is_file($chkFile)) {
                    include_once $chkFile;
                    break 2;
                }
            }
        }
    }
    if (!\class_exists('dynoser\\autoload\\AutoLoadSetup')) {
            \spl_autoload_register(function ($classFullName) use ($scanClassFileFn) {
            $file = $scanClassFileFn($classFullName);
            if ($file) {
                require_once $file;
            }
        });
    }
}

if (!empty($optionsArr['install'])) {
    $className = $optionsArr['install'];
    if (true === $className && !empty($GLOBALS['argv'][1])) {
        $className = $GLOBALS['argv'][1];
    }
    if (!$className) {
        die("Not specified class-name for --install\n");
    }
    if (\is_string($className)) {
        $classInstArr = [$className];
    } elseif(\is_array($className)) {
        $classInstArr = $className;
    } else {
        die("Unsupported --install option type\n");
    }
    foreach($classInstArr as $className) {
        $classFullName = \trim(\strtr($className, '/', '\\'), '\\ ');

        echo "Try install class: '$classFullName' ... ";
    
        try {
            $res = AutoLoader::autoLoad($classFullName, false);
            if ($res) {
                echo "OK\n";
            } else {
                echo "Not found\n";
            }

        } catch (\Throwable $e) {
            $error = $e->getMessage();
            echo "\\Exception: $error \n";
        }
    }
    die("stop");
}


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

if (empty($optionsArr) || !empty($optionsArr['help']) || !empty($optionsArr['h'])) {
    echo <<<VIEWHELP
     $myOwnName
    ----------------------------------------
     call:
    php hashsig.php <url or dir> [options]
    ----------------------------------------
    options:
     [download and verify]
    1) you must specify the source:
      --path=path/to/package    - path to the package being checked
      OR
      --url=url/to/checking
    2) if you whant checking package only:
      --check                   - set check option to prevent write-mode
    3) if you whant to unpack package, need specified target directory:
      --target=path/to
    ----------------------------------------
     [write mode]    -- to sign packages you must have a key installed (see below)
      --write                   - set write option to activate write-mode
      --path=path/to/package    - path to the package to be hashed-signed and packaged
      OR
      --pathfrom=path/to/file   - path to one of file in the package
    ----------------------------------------
     [names]
      --name  - specified name of package, for ex. --name=test will create "test.hashsig.zip"
      --autonamebypath  - automatic calc name based on the name of the last folder (except "src")
      --pathfrom - when this option used for an existing package, the existing name will be taken
    ----------------------------------------
      [KEY]
      --key=path/to/file        - path to the key file
      --gengen                  - generate a new key
      --keyrewrite              - overwrite key file if it exist
      --password=your-password  - (optional) password for encrypt/dectypt key file
      You may set environment:
        HASHSIG_KEYFILE         - the same as --key
        HASHSIG_PASSWORD        - the same as --password  (optional)
    ----------------------------------------
      [file scanning]
      --pattern=*.php           - mask for searching for files included in a package
      --exclude=/index.php      - exclude files and folders (dont add to package)
        Several options --pattern=... and --exclude=... can be specified
      --maxsize=number          - maximum size of files included in the package (bytes)
      --maxfiles=number         - maximum number of files included in a package
      After the package is created, the search options are saved in file <name>.hashsig.json
      Нou can edit the options in the file <name>.hashsig.json and run the packaging again.
    VIEWHELP;
    die;
}

$rewriteOptions = [];

try {
  foreach($optionsArr as $optName => $optValue) {
    switch($optName) {
    case 'version':
    case 'v':
        die($myOwnName);
    case 'url':
    case 'from':
    case 'fromurl':
        if (\filter_var($optValue, \FILTER_VALIDATE_URL)) {
            $url = $optValue;
        } else {
            throw new \Exception("Invalid url=$optValue");
        }
        break;
    case 'frompath':
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
                $maxStepUp = 3;
                $currStep = 0;
                while (\strrpos($srcPath, '/')) {
                    // scan config files by mask *.hashsig.json
                    WalkDir::$fileCountThreshold = 200;
                    WalkDir::$fileCountTotal = 0;
                    $hashSigFilesArr = WalkDir::getFilesArr($srcPath, false, '*' . $configExt);
                    if (empty($hashSigFilesArr)) {
                        // scan *.hashsig.zip files
                        $hashSigFilesArr = WalkDir::getFilesArr($srcPath, false, '*' .  HashSigBase::HASHSIG_FILE_EXT . '.zip');
                    }
                    if (!empty($hashSigFilesArr)) {
                        echo "Found:\n";
                        foreach($hashSigFilesArr as $n => $hashSigConfig) {
                            echo " $hashSigConfig\n";
                            if ($n && empty($optionsArr['getfirst'])) {
                                throw new \Exception("You may use option --getfirst");
                            }
                        }
                        break;
                    }
                    if (++$currStep > $maxStepUp) {
                        echo "(Directory MaxStepUp=$maxStepUp limit reached)\n";
                        break;
                    } else {
                        echo "(Step up from: $srcPath)\n";
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
    case 'a':
    case 'nonsmap':
    case 'getfirst':
        break;
    default:
        echo "Unknown option: $optName\n";
    }
  }
} catch (\Throwable $e) {
    $error = $e->getMessage();
    die("ERROR options: $error \n BREAK\n");
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
            $pkgKeyHex = \bin2hex($chkHSobj->lastSuccessPubKeyBin);
            echo ($kobj && $kobj->pub_key === $pkgKeyHex) ? " (it is my own pubkey)\n" : " !!! FOREING PUBLIC KEY !!!\n";

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
