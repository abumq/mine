<?php

///
/// This script generates include/mine.h
/// file. Development is done on separate
/// modules for ease of development
///

$lib_version = "Unreleased";

$output_template = <<<EOT
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

#ifndef MINE_H
#define MINE_H

{{includes}}
namespace mine {
{{code}}
} // namespace mine
#endif // MINE_H

EOT;

$src_list = array(
    "src/base16.h",
    "src/base64.h",
    "src/aes.h",
    "src/rsa.h",
    "src/zlib.h",
);

$includes = array();
$lines = "";

foreach ($src_list as $filename) {
    $fd = @fopen($filename, "r");
    if ($fd) {
        $namespace_started = false;
        while (($line = fgets($fd, 2048)) !== false) {
            if ($pos = (strpos($line, "#include")) === 0) {
                $includes[] = substr($line, $pos + strlen("#include"));
            } else if ($pos = (strpos($line, "namespace mine {")) === 0) {
                $namespace_started = true;
            } else if ($pos = (strpos($line, "} // end namespace mine")) === 0) {
                $namespace_started = false;
            } else if ($namespace_started && strpos($line, "#include") === false) {
                $lines .= $line;
            }
        }
        if (!feof($fd)) {
            die("Error: unexpected fgets() fail");
        }

        fclose($fd);
    }
    
}
$includes = array_unique($includes, SORT_STRING);
$includes_str = "";
foreach ($includes as $incl) {
    $includes_str .= "#include $incl";
}

$final = str_replace("{{includes}}", $includes_str, $output_template);

$final = str_replace("{{code}}", $lines, $final);
$final = str_replace("{{version}}", $lib_version, $final);

file_put_contents("include/mine.h", $final);
