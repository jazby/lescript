<?php

namespace Jazby\Lescript;

class FileClient
{
    public function isDirectory($directory)
    {
        if (!file_exists($directory) && !@mkdir($directory, 0755, true)) {
            throw new \RuntimeException("Directory doesn't exist or not writable");
        }
        return true;
    }

    public function isFile($path, $name)
    {
        if (!is_dir($path) || !is_file($path . '/' . $name)) {
            throw new \RuntimeException("File doesn't exist.");
        }
        return true;
    }

    public function writeContent($path, $content)
    {
        file_put_contents($path, $content);
        chmod($content, 0644);
    }

    public function removeFile($tokenPath)
    {
        @unlink($tokenPath);
    }
}
