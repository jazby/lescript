<?php
require __DIR__ . '/../vendor/autoload.php';

// you can use any logger according to Psr\Log\LoggerInterface
class Logger
{
    function __call($name, $arguments)
    {
        echo date('Y-m-d H:i:s') . " [$name] ${arguments[0]}\n";
    }
}

$logger = new Logger();

try {

    $le = new \Jazby\Lescript\Lescript('/certificate/storage', '/var/www/test.com', $logger);
    # or without logger:
    # $le = new Analogic\ACME\Lescript('/certificate/storage', '/var/www/test.com');
    $le->initAccount();
    $le->signDomains(['test.com', 'www.test.com']);
} catch (\Exception $e) {

    $logger->error($e->getMessage());
    $logger->error($e->getTraceAsString());
}
