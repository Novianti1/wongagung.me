<?php
/**
 * deploy.php by Hayden Schiff (oxguy3)
 * Available at https://gist.github.com/oxguy3/70ea582d951d4b0f78edec282a2bebf9
 * 
 * No rights reserved. Dedicated to public domain via CC0 1.0 Universal.
 * See https://creativecommons.org/publicdomain/zero/1.0/ for terms.
 */
 
// random string of characters; must match the "Secret" defined in your GitHub webhook
define('GITHUB_SECRET', 'qwertyuiop1234567890');
// name of the git branch that you're deploying
define('GITHUB_BRANCH', 'master');
// your email address, where you'll receive notices of deploy successes/failures
define('EMAIL_RECIPIENT', 'johndoe@example.com');
// domain of your website
define('SITE_DOMAIN', 'example.com');
// port number of SSH for your server (may vary by hosting provider -- for me, it was 21098)
define('SSH_PORT', 22);
// username for SSH (should be the same as your cPanel login username)
define('SSH_USERNAME', 'johndoe');
// filename for the keypair to use -- no need to change this if you follow the readme instructions
define('KEYPAIR_NAME', 'deploy');
// the passphrase for your keypair
define('KEYPAIR_PASSPHRASE', 'abc123');
// END OF CONFIGURATION OPTIONS
/**
 * Convenience function for sending emails
 *
 * If you want to disable email sending, just replace the content of this
 * function with "return true;".
 */
function sendEmail($success, $message)
{
    $headers = 'Content-type: text/plain' . "\r\n" .
        'From: admin@'.SITE_DOMAIN;
    $subject = '['.SITE_DOMAIN.'] ';
    if ($success) {
        $subject .= 'Deploy success';
    } else {
        $subject .= 'Deploy failure';
        $headers .= "\r\n" .
            'X-Priority: 1 (Highest)' . "\r\n" .
            'X-MSMail-Priority: High' . "\r\n" .
            'Importance: High';
    }
    return mail(
        EMAIL_RECIPIENT,
        $subject,
        $message,
        $headers
    );
}
try {
    $signature = $_SERVER['HTTP_X_GITHUB_EVENT'];
    if (is_null($signature) || $signature != 'push') {
        header('HTTP/1.0 400 Bad Request');
        die('go away');
    }
    $payload = file_get_contents('php://input');
    // get the signature out of the headers and split it into parts
    $signature = $_SERVER['HTTP_X_HUB_SIGNATURE'];
    $sigParts  = explode('=', $signature);
    if (sizeof($sigParts) != 2) {
        throw new Exception('Bad signature: wrong number of \'=\' chars');
    }
    $sigAlgo = $sigParts[0];
    $sigHash = $sigParts[1];
    // verify that the signature is correct
    $hash = hash_hmac($sigAlgo, $payload, GITHUB_SECRET);
    if ($hash === false) {
        throw new Exception("Unknown signature algo: $sigAlgo");
    }
    if ($hash != $sigHash) {
        throw new Exception("Signatures didn't match. Ours: '$hash', theirs: '$sigHash'.");
    }
    // read the payload
    $data = json_decode($payload);
    if (is_null($data)) {
        throw new Exception('Failed to decode JSON payload');
    }
    // make sure it's the right branch
    $branchRef = $data->ref;
    if ($branchRef != 'refs/heads/'.GITHUB_BRANCH) {
        die("Ignoring push to '$branchRef'");
    }
    // ssh into the local server
    $sshSession = ssh2_connect('localhost', SSH_PORT);
    $authSuccess = ssh2_auth_pubkey_file(
        $sshSession,
        SSH_USERNAME,
        '/home/'.SSH_USERNAME.'/.ssh/'.KEYPAIR_NAME.'.pub',
        '/home/'.SSH_USERNAME.'/.ssh/'.KEYPAIR_NAME,
        KEYPAIR_PASSPHRASE
    );
    if (!$authSuccess) {
        throw new Exception('SSH authentication failure');
    }
    // start a shell session
    $shell = ssh2_shell($sshSession, 'xterm');
    if ($shell === false) {
        throw new Exception('Failed to open shell');
    }
    stream_set_blocking($shell, true);
    stream_set_timeout($shell, 15);
    // run the commands
    $output = '';
    $endSentinel = "!~@#_DONE_#@~!";
    fwrite($shell, 'cd ~/public_html' . "\n");
    fwrite($shell, 'git pull' . "\n");
    fwrite($shell, 'echo ' . escapeshellarg($endSentinel) . "\n");
    while (true) {
        $o = stream_get_contents($shell);
        if ($o === false) {
            throw new Exception('Failed while reading output from shell');
        }
        $output .= $o;
        if (strpos($output, $endSentinel) !== false) {
            break;
        }
    }
    fclose($shell);
    fclose($sshSession);
    $mailBody = "GitHub payload:\r\n"
        . print_r($data, true)
        . "\r\n\r\n"
        . "Output of `git pull`:\r\n"
        . $output
        . "\r\n"
        . 'That\'s all, toodles!';
    $mailSuccess = sendEmail(true, $mailBody);
} catch (Exception $e) {
    $mailSuccess = sendEmail(false, strval($e));
}
if(!$mailSuccess) {
    header('HTTP/1.0 500 Internal Server Error');
    die('Failed to send email to admin!');
}
die("All good here!");
?>
