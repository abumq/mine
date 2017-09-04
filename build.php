<?php

///
/// This script generates mine.h and mine.cc
/// files. Development is done on separate
/// modules for ease of development
///

$lib_version = "Unreleased";

$header_template = <<<EOT
//
//  Bismillah ar-Rahmaan ar-Raheem
//
//  Mine ({{version}})
//  Single header minimal cryptography library
//
//  Copyright (c) 2017 Muflihun Labs
//
//  This library is released under the Apache 2.0 license
//  https://github.com/muflihun/mine/blob/master/LICENSE
//
//  https://github.com/muflihun/mine
//  https://muflihun.github.io/mine
//  https://muflihun.com
//

#ifndef MINE_CRYPTO_H
#define MINE_CRYPTO_H

{{includes}}
namespace mine {
{{code}}
} // namespace mine
#endif // MINE_CRYPTO_H

EOT;

$source_template = <<<EOT
//
//  Bismillah ar-Rahmaan ar-Raheem
//
//  Mine ({{version}})
//  Single header minimal cryptography library
//
//  Copyright (c) 2017 Muflihun Labs
//
//  This library is released under the Apache 2.0 license
//  https://github.com/muflihun/mine/blob/master/LICENSE
//
//  https://github.com/muflihun/mine
//  https://muflihun.github.io/mine
//  https://muflihun.com
//
{{includes}}
#include "mine.h"

using namespace mine;
{{code}}
EOT;

function includeArrayToStr($includes) {
    $includes = array_unique($includes, SORT_STRING);
    $includes_str = "";
    foreach ($includes as $incl) {
        $includes_str .= "#include $incl";
    }
    return $includes_str;
}

function resolveTemplate($template, $includes, $lines, $lib_version, $filename) {
    $includes_str = includeArrayToStr($includes);
    $final = str_replace("{{includes}}", $includes_str, $template);

    $final = str_replace("{{code}}", $lines, $final);
    $final = str_replace("{{version}}", $lib_version, $final);

    file_put_contents($filename, $final);
}

$headers_list = array(
    "src/mine-common.h",
    "src/base16.h",
    "src/base64.h",
    "src/aes.h",
    "src/rsa.h",
    "src/zlib.h",
);

$includes = array();
$lines = "";

foreach ($headers_list as $filename) {
    $fd = @fopen($filename, "r");
    if ($fd) {
        $namespace_started = false;
        while (($line = fgets($fd, 2048)) !== false) {
            if ($pos = (strpos(trim($line), "#include")) === 0) {
                // don't include header of the file
                if (strpos(trim($line), "#include \"src/") === false) {
                    $includes[] = substr($line, $pos + strlen("#include"));
                }
            } else if ($pos = (strpos(trim($line), "namespace mine {")) === 0) {
                $namespace_started = true;
            } else if ($pos = (strpos(trim($line), "} // end namespace mine")) === 0) {
                $namespace_started = false;
            } else if ($namespace_started && strpos(trim($line), "#include") === false) {
                $lines .= $line;
            }
        }
        if (!feof($fd)) {
            die("Error: unexpected fgets() fail");
        }

        fclose($fd);
    }
    
}
resolveTemplate($header_template, $includes, $lines, $lib_version, "package/mine.h");

// source file

$source_list = array(
    "src/mine-common.cc",
    "src/base16.cc",
    "src/base64.cc",
    "src/aes.cc",
    "src/rsa.cc",
    "src/zlib.cc",
);

$includes = array();
$lines = "";

foreach ($source_list as $filename) {
    $fd = @fopen($filename, "r");
    if ($fd) {
        $codeStarted = false;
        while (($line = fgets($fd, 4096)) !== false) {
            if (!$codeStarted && $pos = (strpos(trim($line), "//")) === false) {
                $codeStarted = true; // we ignore comment of the file
            } else if ($codeStarted && $pos = (strpos(trim($line), "#include")) === 0) {
                // don't include header of the file
                if (strpos(trim($line), "#include \"src/") === false) {
                    $includes[] = substr($line, $pos + strlen("#include"));
                }
            } else if ($codeStarted && $pos = (strpos(trim($line), "using namespace mine")) === 0) {
                // ignore namespace as we have in template
            } else if ($codeStarted && strpos(trim($line), "#include") === false) {
                $lines .= $line;
            }
        }
        if (!feof($fd)) {
            die("Error: unexpected fgets() fail");
        }

        fclose($fd);
    }
    
}
resolveTemplate($source_template, $includes, $lines, $lib_version, "package/mine.cc");
