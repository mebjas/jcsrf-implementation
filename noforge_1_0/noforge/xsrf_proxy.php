<?php

// DISCLAIMER:
// this is a research prototype and not suitable for production environments;
// use at your own risk

// DON'T FORGET for every new application
// - add an appropriate alias rule to httpd.conf
// - adjust the application-specific config section in this file
// - use the preprocessing script for exit, header etc.
// - make sure that your web server provides $_SERVER['UNIQUE_ID'],
//   and that it is not modified by the target application

// NOTE: using this script keeps PHP from transparent url rewriting

// NOTE: the names of all global variables have been prefixed with a special
// string to prevent mixing up with the target application's variables;
// you can change this prefix with a simple search&replace

// use AliasMatches such as this in Apache:
// AliasMatch ^/mybloggie213beta/.*\.php /opt/lampp/htdocs/xsrf_proxy.php

// for executing Java programs, the class (or jar) files have to be in
// the classpath; can be checked with echo(shell_exec("printenv"));

// CONFIG ***************************************************************************

// GENERAL

$_xx_info['token_name'] = 'xsrf_token';  // the name of the GET parameter used for transporting the token
$_xx_info['document_root'] = '/opt/lampp/htdocs';  // where your web server stores the content
$_xx_info['tokentable_file'] = '/tmp/token_table';  // the file used for storing the token table
$_xx_info['session_timeout'] = 1500;   // in seconds; set this to session.gc_maxlifetime + a little more
// $_xx_info['session_name']= 'app-specific';   // the name of the request parameter used for transporting the session id
                                                // LATER: you could also add a wrapper for session_name() to
                                                // detect changes to this value
// $_xx_info['disarm_url'] = 'app-specific';   // this url is provided when a supposed XSRF attack is detected
$_xx_info['whitelist'] = array();


// APPLICATION-SPECIFIC

if (substr($_SERVER['REQUEST_URI'], 1, 9) == 'phpbb2019') {
    $_xx_info['target_app'] = 'phpbb2019';
} else if (substr($_SERVER['REQUEST_URI'], 1, 14) == 'phpmyadmin2802') {
    $_xx_info['target_app'] = 'phpmyadmin2802';
} else if (substr($_SERVER['REQUEST_URI'], 1, 9) == 'phpnuke70') {
    $_xx_info['target_app'] = 'phpnuke70';
} else if (substr($_SERVER['REQUEST_URI'], 1, 6) == 'cpg144') {
    $_xx_info['target_app'] = 'cpg144';
} else if (substr($_SERVER['REQUEST_URI'], 1, 15) == 'squirrelmail146') {
    $_xx_info['target_app'] = 'squirrelmail146';
} else {
    $_xx_info['target_app'] = 'default';
}

if ($_xx_info['target_app'] == 'default') {
    $_xx_info['session_name'] = 'PHPSESSID';
    $_xx_info['disarm_url'] = 'http://localhost/default.html';
} else if ($_xx_info['target_app'] == 'phpbb2019') {
    // phpBB 2.0.19
    $_xx_info['session_name'] = 'phpbb2mysql_sid';
    $_xx_info['disarm_url'] = 'http://localhost/phpbb2019/index.php';
} else if ($_xx_info['target_app'] == 'phpmyadmin2802') {
    // phpMyAdmin 2.8.0.2
    $_xx_info['session_name'] = 'phpMyAdmin';
    $_xx_info['disarm_url'] = 'http://localhost/phpmyadmin2802/index.php';
    $_xx_info['whitelist']['phpmyadmin.css.php'] = 1;
} else if ($_xx_info['target_app'] == 'gallery204') {
    // Gallery 2.0.4 (XSRF doesn't seem to work here anyway)
    $_xx_info['session_name'] = 'GALLERYSID';
    $_xx_info['disarm_url'] = 'http://localhost/gallery204/main.php';
} else if ($_xx_info['target_app'] == 'phpnuke70') {
    // PhpNuke 7.0
    $_xx_info['session_name'] = 'admin';   // for normaler users, this is "user"
    $_xx_info['disarm_url'] = 'http://localhost/phpnuke70/html/index.php';

    // turn off notices, or you'll be flooded:
    ini_set('error_reporting', 'E_ALL & ~E_NOTICE');
    // requires register_globals to work correctly
    ini_set('register_globals', 'On');
} else if ($_xx_info['target_app'] == 'cpg144') {
    // Coppermine Photo Gallery 1.4.4
    // the session name depends on the client; the details can be found
    // coppermine.inc.php; integrate it here if you need it
    $_xx_info['session_name'] = '55a26f7fb801303f85655f06a90278a8';
    $_xx_info['disarm_url'] = 'http://localhost/cpg144/index.php';
} else if ($_xx_info['target_app'] == 'squirrelmail146') {
    // Squirrelmail 1.4.6
    $_xx_info['session_name'] = 'SQMSESSID';
    $_xx_info['disarm_url'] = 'http://localhost/squirrelmail146/src/webmail.php';
} else {
    die('Configured for unknown application');
}

// MAIN PROCEDURES ******************************************************************

// load token table: array SID -> token
$_xx_info['token_table'] = _xx_load_token_table($_xx_info['tokentable_file']);

_xx_log('beginning for file ' . $_SERVER['SCRIPT_NAME'] . ', ' . $_SERVER['UNIQUE_ID']);
$_xx_info['bare_scriptname'] = _xx_extract_scriptname($_SERVER['SCRIPT_NAME']);
_xx_log('request_uri: ' . $_SERVER['REQUEST_URI']);
_xx_log('bare scriptname: ' . $_xx_info['bare_scriptname']);

// we need this for possible "Content-type" headers
$_xx_info['rewrite_allowed'] = true;

// if the user tries to resume a session...
// (and if the target script is not in the whitelist)
if (_xx_request_contains_sid($_xx_info, &$_xx_info['sid']) && !isset($_xx_info['whitelist'][$_xx_info['bare_scriptname']]) ) {

    _xx_log('request contains sid...');

    // if we've seen this SID before (and hence, have added it to the token table)...
    if (isset($_xx_info['token_table'][$_xx_info['sid']]['token'])) {

        _xx_log('we have seen this sid before...');

        // ..., then the request is expected to contain a token (since in this case, we've already performed rewriting)
        $_xx_info['token'] = _xx_get_token_from_request($_xx_info);

        // we expect to see this token
        $_xx_info['expected_token'] = $_xx_info['token_table'][$_xx_info['sid']]['token'];

        // if the request doesn't contain a token
        if ($_xx_info['token'] == -1) {
            // echo 'Disarm 1, ' . $_xx_info['bare_scriptname'] . '<br/>';
            echo 'Disarm 1, ' . $_SERVER['REQUEST_URI'] . '<br/>';
            _xx_log('disarm 1');
            _xx_disarm($_xx_info, $_xx_info['expected_token']);
        }

        // check if the token is associated to the request sid
        //if (!_xx_valid_token($_xx_info['token'], $_xx_info['sid'])) {
        if ($_xx_info['token'] != $_xx_info['expected_token']) {
            // echo 'Disarm 2, ' . $_xx_info['bare_scriptname'] . '<br/>';
            echo 'Disarm 2, ' . $_SERVER['REQUEST_URI'] . '<br/>';
            _xx_log('disarm 2');
            _xx_disarm($_xx_info, $_xx_info['expected_token']);
        }

        // update timestamp
        $_xx_info['token_table'][$_xx_info['sid']]['time'] = time();

    } else {
        // if we've never seen this SID before, we haven't performed rewriting yet;
        // add a new entry to the token table with this sid and a newly generated token
        _xx_log('generating token for this sid...' . $_xx_info['sid']);
        $_xx_info['token'] = _xx_generate_token();
        $_xx_info['token_table'][$_xx_info['sid']]['token'] = $_xx_info['token'];
        $_xx_info['token_table'][$_xx_info['sid']]['time'] = time();
    }

}

/*
// remove stale entries from the token table;
// LATER: don't do this for every request (not very efficient)
reset($_xx_info['token_table']);    // reset array pointer, to be safe
$_xx_info['entry'] = each($_xx_info['token_table']);    // start traversing the array
while ($_xx_info['entry'] !== false) {
    // if this entry is around for longer than the session timeout, remove it
    if (time() - $_xx_info['entry']['value']['time'] > $_xx_info['session_timeout']) {
        unset($_xx_info['token_table'][$_xx_info['entry']['key']]);
    }
    $_xx_info['entry'] = each($_xx_info['token_table']);
}
reset($_xx_info['token_table']);    // reset array pointer, to be safe
unset($_xx_info['entry']);  // we don't need this one any more
*/

// store the token table
_xx_store_token_table($_xx_info['token_table'], $_xx_info['tokentable_file']);
$_xx_info['token_table'] = 0;  // don't store the token table again with the state


// *** PASS ***

$_xx_info['target_script_complete'] = $_xx_info['document_root'] . $_SERVER['SCRIPT_NAME'];   // name of target script + absolute filesystem path  
$_xx_info['target_script_path'] = dirname($_xx_info['target_script_complete']);   // absolute filesystem path to target script
$_xx_info['target_script_name'] = basename($_SERVER['SCRIPT_NAME']);  // path-less name of target script

_xx_write_state($_xx_info);

// rewrite $_SERVER environment (so that the target script doesn't notice
// that it's located behind this proxy)
_xx_rewrite_server($_xx_info);

// start output buffering
ob_start();

// set current working directory
chdir($_xx_info['target_script_path']);

// include the target script;
// this include statement MUST be issued from the global scope;
// otherwise, you'll confuse and break the target application
_xx_log('including target script');
include $_xx_info['target_script_complete'];
_xx_log('normal return from inclusion');

$_xx_info = _xx_read_state();

// rewrite and return
echo _xx_process_reply($_xx_info);
_xx_remove_state();





function _xx_process_reply($_xx_info) {

    _xx_log('deciding what to do with reply...; ' . $_SERVER['UNIQUE_ID']);

    if (ob_get_level() < 1) {
        // if our output buffer has already been been stopped,
        // there is nothing we can do
        _xx_log('Output buffer broken by target application');
        die('Output buffer broken by target application');
    }
    while (ob_get_level() != 1) {
        // the target application left open output buffers: flush them
        ob_end_flush();
    }
    $reply = ob_get_contents();
    ob_end_clean();

    // if we don't know about a session ID, we don't rewrite the reply
    if ($_xx_info['sid'] == null) {
        _xx_log('Not rewriting reply (no sid)');
        return $reply;
    }

    // if the current file is in the whitelist, we don't rewrite it either
    if(isset($_xx_info['whitelist'][$_xx_info['bare_scriptname']])) {
        _xx_log('Not rewriting reply (whitelist)');
        return $reply;
    }


    // if we've decided that rewriting is not allowed (probably because an image
    // content type header was sent), we don't rewrite
    if (!$_xx_info['rewrite_allowed']) {
        _xx_log('Not rewriting reply (not allowed)');
        return $reply;
    }

    _xx_log('Rewriting reply!');
    return _xx_rewrite_reply($_xx_info, $reply);
}

// rewrite entries of the $_SERVER array so that the included file doesn't notice
// that it was included: make it think it was called directly
function _xx_rewrite_server($_xx_info) {

    // debug aid
    $debug = 0;
    
    if ($debug) {
        echo '<pre>';
        print_r($_SERVER);
    }

    if (isset($_SERVER['SCRIPT_FILENAME'])) {
        // in:  absolute filesystem name of this xsrf proxy script
        // out: absolute filesystem name of the target script
        $_SERVER['SCRIPT_FILENAME'] = $_xx_info['target_script_complete'];
    }
    
    /* obsolete
    if (isset($_SERVER['QUERY_STRING'])) {
        // in:  query string (= the stuff after the '?'), including xsrf proxy stuff
        // out: query string without xsrf proxy stuff
        $newval = preg_replace("/$target_script_param=[^&]*&?/", '', $_SERVER['QUERY_STRING']);
        $_SERVER['QUERY_STRING'] = $newval;
    }
    */
    
    /* not necessary with Apache Aliasing
    if (isset($_SERVER['REQUEST_URI'])) {
        // requires: $_SERVER['QUERY_STRING'] must have been processed already
        //
        // in:  request uri of this xsrf proxy script (e.g., "/xsrf/proxy.php"), + params!
        // out: request uri of the target script, + params!
        if (empty($_SERVER['QUERY_STRING'])) {
            $_SERVER['REQUEST_URI'] = "/{$_xx_info['target_script_complete']}";
        } else {
            $_SERVER['REQUEST_URI'] = "/{$_xx_info['target_script_complete']}?${_SERVER['QUERY_STRING']}";
        }
    }
    */
    
    /* not necessary with Apache Aliasing
    if (isset($_SERVER['SCRIPT_NAME'])) {
        // in:  request uri of this xsrf proxy script (e.g., "/xsrf/proxy.php"), without params
        // out: request uri of the target script, without params
        $_SERVER['SCRIPT_NAME'] = "/{$_xx_info['target_script_complete']}";
    }
    */
    
    /* not necessary with Apache Aliasing
    if (isset($_SERVER['PHP_SELF'])) {
        // seems to be identical to SCRIPT_NAME
        $_SERVER['PHP_SELF'] = $_SERVER['SCRIPT_NAME'];
    }
    */

    if (isset($_SERVER['PATH_TRANSLATED'])) {
        // seems to be identical to SCRIPT_FILENAME
        $_SERVER['PATH_TRANSLATED'] = $_SERVER['SCRIPT_FILENAME'];
    }

    if (isset($_SERVER['argv'])) {
        // requires: QUERY_STRING must have been processed already
        // if there are GET parameters, the argv array contains one entry (index 0)
        // with the query string; else: no entries to this array
        if (empty($_SERVER['QUERY_STRING'])) {
            unset($_SERVER['argv'][0]);
            $_SERVER['argc'] = 0;
        } else {
            $_SERVER['argv'][0] = $_SERVER['QUERY_STRING'];
            $_SERVER['argc'] = 1;
        }
    }
    
    if ($debug) {
        print_r($_SERVER);
        exit;
    }
}

// does the request contain a session ID? if it does, the param receives this ID's value
function _xx_request_contains_sid($_xx_info, &$sid_in_request) {

    if (isset($_REQUEST[$_xx_info['session_name']])) {
        $sid_in_request = $_REQUEST[$_xx_info['session_name']];
        return true;
    } else {
        $sid_in_request = null;
        return false;
    }
}


// returns the token (i.e., a string) from the request, or -1 if there is no token
function _xx_get_token_from_request($_xx_info) {

    if (isset($_REQUEST[$_xx_info['token_name']])) {
        return $_REQUEST[$_xx_info['token_name']];
    } else {
        return -1;
    }
}

// TOKEN TABLE FUNCTIONS ***********************************************************

// returns the token table array
function _xx_load_token_table($filename) {
    if (is_file($filename)) {
        $serialized = file_get_contents($filename);
        return unserialize($serialized);
    } else {
        return array();
    }
}

// writes the token table array to a file
function _xx_store_token_table($token_table, $filename) {
    $file = fopen($filename, 'w');
    fwrite($file, serialize($token_table));
    fclose($file);
}

// *********************************************************************************

// redirects to some harmless page, or
// deletes request parameters;
// a solution that is convenient for the user and simple to implement
// would be to redirect to a harmless main page
function _xx_disarm($_xx_info, $expected_token) {
    echo 'It seems that an XSRF attack is taking place...<br/>';
    echo "Please follow this link to <a href='{$_xx_info['disarm_url']}?{$_xx_info['token_name']}=$expected_token'>proceed</a>.";
    exit;  // don't continue after disarming
}


// generates a random token (string) and returns it
function _xx_generate_token() {
    return rand(1000000, 10000000);
}

// embeds the given token into all links and forms in the given reply document;
// returns the rewritten document
function _xx_rewrite_reply($_xx_info, $reply) {

    $descriptorspec = array(
       0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
       1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
       2 => array("pipe", "w") 
    );


    $token_table = _xx_load_token_table($_xx_info['tokentable_file']);
    $token = $token_table[$_xx_info['sid']]['token'];
    
    _xx_log('Invoking rewriter with params ' . $_xx_info['token_name'] . ', ' . $token);
    $process = proc_open("java TokenRewriter {$_xx_info['token_name']} {$token}", $descriptorspec, $pipes);

    if (is_resource($process)) {

        fwrite($pipes[0], $reply);
        fclose($pipes[0]);

        $modReply = '';
        while (!feof($pipes[1])) {
            $modReply .= fgets($pipes[1]);
        }
        fclose($pipes[1]);
        
        /*
        $modReply = fgets($pipes[1]);
        // fpassthru($pipes[1]);
        fclose($pipes[1]);
        */

        $err = fgets($pipes[2]);
        fclose($pipes[2]);
        if (!empty($err)) {
            // report error
            _xx_log('Error during invocation: ' . $err);
            die('An error occurred during invocation: <br/>' . $err);
        }

        $return_value = proc_close($process);

    } else {
        // report error
        _xx_log('Error during invocation (not a resource)');
        die('An error occurred during invocation (not a resource)');
    }

    return $modReply;
}

// receives a script name that may contain a path prefix as well as a parameter
// postfix (e.g., "./path/to/script.php?x=y), and returns only the script name
function _xx_extract_scriptname($script_name) {

    $right_end = strrpos($script_name, '?');
    if ($right_end === false) {
        $right_end = strlen($script_name);
    }
    $left_end = strrpos($script_name, '/');
    if ($left_end === false) {
        $left_end = -1;
    }
    $script_name = substr($script_name, $left_end + 1, $right_end - $left_end - 1);
    return $script_name;
}

function _xx_log($msg) {
    // uncomment this to disable logging (makes it much faster)
    return;
    
    // note that this logging technique doesn't take into account that multiple
    // requests (e.g., framesets) can be handled in parallel; hence, the order in the log
    // output is not deterministic; don't get confused by this;
    // alternatively, you could create a separate logfile for each request; for
    // this purpose, use $_SERVER['UNIQUE_ID'] (see STATE FUNCTIONS)
    $handle = fopen('/tmp/xsrf_log.txt', 'a');
    fwrite($handle, $msg . "\n");
    fclose($handle);
}

// STATE FUNCTIONS *****************************************************************
// some applications are evil and destroy necessary global or request variables;
// to prevent information loss, we store all our information into a single array,
// write this array to a file before calling the target application, and read the
// array back afterwards; to keep information from different requests apart, we
// use $_SERVER['UNIQUE_ID'] (otherwise, we would mix it up in case of parallel
// processing, e.g., in case of framesets)

function _xx_write_state($store_me) {
    // if you want to change the filename, you have to change it in the
    // other functions as well!
    $filename = '/tmp/xsrf_state_' . $_SERVER['UNIQUE_ID'];  
    $file = fopen($filename, 'w');
    fwrite($file, serialize($store_me));
    fclose($file);
}

function _xx_read_state() {
    // if you want to change the filename, you have to change it in the
    // other functions as well!
    $filename = '/tmp/xsrf_state_' . $_SERVER['UNIQUE_ID'];
    if (is_file($filename)) {
        $serialized = file_get_contents($filename);
        return unserialize($serialized);
    } else {
        return null;
    }
}

// call this function at every exit point (or else, you'll end up with a large number
// of state files)
function _xx_remove_state() {
    // if you want to change the filename, you have to change it in the
    // other functions as well!
    $filename = '/tmp/xsrf_state_' . $_SERVER['UNIQUE_ID'];
    if (is_file($filename)) {
        unlink($filename);
    }
}



// WRAPPERS ************************************************************************

function _xsrf_session_start() {
    
    _xx_log('caught session_start()');
    
    // recover state and token table
    $_xx_info = _xx_read_state();
    $_xx_info['token_table'] = _xx_load_token_table($_xx_info['tokentable_file']);

    $retme = session_start();

    // write down session ID
    $_xx_info['sid'] = session_id();

    // if we haven't generated at token for this ID yet: do it now
    if (!isset($_xx_info['token_table'][$_xx_info['sid']]['token'])) {
        $_xx_info['token'] = _xx_generate_token();
        $_xx_info['token_table'][$_xx_info['sid']]['token'] = $_xx_info['token'];
    }
    // update timestamp
    $_xx_info['token_table'][$_xx_info['sid']]['time'] = time();

    // store token table and state
    _xx_store_token_table($_xx_info['token_table'], $_xx_info['tokentable_file']);
    $_xx_info['token_table'] = 0;  // don't store the token table again with the state
    _xx_write_state($_xx_info);

    return $retme;
}

function _xsrf_session_id($id = null) {

    if ($id == null) {
        // if this function was called without parameter, the caller
        // just wants to know the current session ID
        return session_id();
    }
    // else: the caller re-sets the session ID

     _xx_log('caught non-null session_id()');
   
    // recover state and token table
    $_xx_info = _xx_read_state();
    $_xx_info['token_table'] = _xx_load_token_table($_xx_info['tokentable_file']);

    $retme = session_id($id);

    // write down session ID
    $_xx_info['sid'] = session_id();

    // if we haven't generated at token for this ID yet: do it now
    if (!isset($_xx_info['token_table'][$_xx_info['sid']]['token'])) {
        $_xx_info['token'] = _xx_generate_token();
        $_xx_info['token_table'][$_xx_info['sid']]['token'] = $_xx_info['token'];
    }
    // update timestamp
    $_xx_info['token_table'][$_xx_info['sid']]['time'] = time();

    // store token table and state
    _xx_store_token_table($_xx_info['token_table'], $_xx_info['tokentable_file']);
    $_xx_info['token_table'] = 0;  // don't store the token table again with the state
    _xx_write_state($_xx_info);

    return $retme;
}

function _xsrf_session_regenerate_id($delete_old_session = false) {

    _xx_log('caught session_regenerate_id()');
    
    // recover state and token table
    $_xx_info = _xx_read_state();
    $_xx_info['token_table'] = _xx_load_token_table($_xx_info['tokentable_file']);

    $retme = session_regenerate_id($delete_old_session);

    // write down session ID
    $_xx_info['sid'] = session_id();

    // if we haven't generated at token for this ID yet: do it now
    if (!isset($_xx_info['token_table'][$_xx_info['sid']]['token'])) {
        $_xx_info['token'] = _xx_generate_token();
        $_xx_info['token_table'][$_xx_info['sid']]['token'] = $_xx_info['token'];
    }
    // update timestamp
    $_xx_info['token_table'][$_xx_info['sid']]['time'] = time();

    // store token table and state
    _xx_store_token_table($_xx_info['token_table'], $_xx_info['tokentable_file']);
    $_xx_info['token_table'] = 0;  // don't store the token table again with the state
    _xx_write_state($_xx_info);

    return $retme;
}

function _xsrf_setcookie($name, $value = '', $expire = 0, $path = '', $domain  = '', $secure = '') {

    _xx_log('caught setcookie() with name = ' . $name . ' and value ' . $value);
    
    // recover state and token table
    $_xx_info = _xx_read_state();
    $_xx_info['token_table'] = _xx_load_token_table($_xx_info['tokentable_file']);

    // if setting the session cookie: write down session ID
    if ($name == $_xx_info['session_name']) {
        if (!empty($value)) {
            $_xx_info['sid'] = $value;
        }
    }

    // if we haven't generated at token for this ID yet: do it now
    if (!isset($_xx_info['token_table'][$_xx_info['sid']]['token'])) {
        $_xx_info['token'] = _xx_generate_token();
        $_xx_info['token_table'][$_xx_info['sid']]['token'] = $_xx_info['token'];
    }
    // update timestamp
    $_xx_info['token_table'][$_xx_info['sid']]['time'] = time();

    // store token table and state
    _xx_store_token_table($_xx_info['token_table'], $_xx_info['tokentable_file']);
    $_xx_info['token_table'] = 0;  // don't store the token table again with the state
    _xx_write_state($_xx_info);

    return setcookie($name, $value, $expire, $path, $domain, $secure);
}

function _xsrf_setrawcookie($name, $value = '', $expire = 0, $path = '', $domain  = '', $secure = '') {

    _xx_log('caught setrawcookie()');
    
    // recover state and token table
    $_xx_info = _xx_read_state();
    $_xx_info['token_table'] = _xx_load_token_table($_xx_info['tokentable_file']);

    // if setting the session cookie: write down session ID
    if ($name == $_xx_info['session_name']) {
        $_xx_info['sid'] = $value;
    }

    // if we haven't generated at token for this ID yet: do it now
    if (!isset($_xx_info['token_table'][$_xx_info['sid']]['token'])) {
        $_xx_info['token'] = _xx_generate_token();
        $_xx_info['token_table'][$_xx_info['sid']]['token'] = $_xx_info['token'];
    }
    // update timestamp
    $_xx_info['token_table'][$_xx_info['sid']]['time'] = time();

    // store token table and state
    _xx_store_token_table($_xx_info['token_table'], $_xx_info['tokentable_file']);
    $_xx_info['token_table'] = 0;  // don't store the token table again with the state
    _xx_write_state($_xx_info);

    return setrawcookie($name, $value, $expire, $path, $domain, $secure);
}

// wrapper around exit() and die()
function _xsrf_exit($status = null) {
    $_xx_info = _xx_read_state();

    _xx_log('caught exit statement, ' . $_SERVER['UNIQUE_ID']);
    $output = _xx_process_reply($_xx_info);
    echo $output;
    _xx_remove_state();
    if ($status == null) {
        exit;
    } else {
        exit($status);
    }

    // no return value
}

// LATER: you could also add a check whether the Location url points to your
// own site, or to another site; only add the token for your own site
function _xsrf_header($string, $replace = true, $http_response_code = -1) {
    $_xx_info = _xx_read_state();

    _xx_log('header in:  ' . $string . ', ' . $_SERVER['UNIQUE_ID']);

    if (preg_match('/^Location:/i', $string) != 0) {
        // this is a Location header
        _xx_log('a location header! sid in request: ' . $_xx_info['sid']);

        // if there exists a SID, we have to add the token to the redirect url
        if ($_xx_info['sid'] != null) {
            _xx_log('appending token to location url!');

            // retrieve URL
            $url = trim(substr($string, 9));

            $quotPos = strpos($url, '?');
            if ($quotPos === false) {
                // there is no ? in the url
                $appendChar = '?';
            } else {
                // there is an '?' in the url
                if ($quotPos == strlen($url) - 1) {
                    // the '?' is at the end if the url
                    $appendChar = '';
                } else {
                    if (substr($url, strlen($url) - 1) == '&') {
                        // the url ends with '&'
                        $appendChar = '';
                    } else {
                        $appendChar = '&';
                    }
                }
            }

            $string .= "$appendChar{$_xx_info['token_name']}={$_xx_info['token']}";
        }
        _xx_remove_state();
    } else if (preg_match('/^Content-type:/i', $string) != 0) {
        // this is a content-type header

        if (preg_match('#image#i', $string)) {
            // don't perform rewriting for image content types
            $_xx_info['rewrite_allowed'] = false;
            _xx_write_state($_xx_info);
        }
    }
    
    _xx_log('header out: ' . $string);
    if ($http_response_code == -1) {
        header($string, $replace);
    } else {
        header($string, $replace, $http_response_code);
    }

    // no return value
    
}

?>
