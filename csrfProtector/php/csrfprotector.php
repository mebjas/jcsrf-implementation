<?php

include_once __DIR__ .'/config/csrfp.config.inc.php';
include_once __DIR__ .'/libs/csrfp.php';

//Initialise CSRFGuard library
csrfProtector::initialise();

/**
 * Rewrites <form> on the fly to add CSRF tokens to them. This can also
 * inject our JavaScript library.
 */
function csrf_ob_handler($buffer, $flags) {

    // Even though the user told us to rewrite, we should do a quick heuristic
    // to check if the page is *actually* HTML. We don't begin rewriting until
    // we hit the first <html tag.
    static $is_html = false;
    if (!$is_html) {
        // not HTML until proven otherwise
        if (stripos($buffer, '<html') !== false) {
            $is_html = true;
        } else {
            return $buffer;
        }
    }

    
    if(!file_exists(CSRFGUARD_SELF .CSRFP_JS)) {
        exit("CSRFGuard js file not found!");
    }

    $script = "<input type='hidden' name='CSRFPROTECTOR_TOKEN_NAME' value='" .csrfProtector::$cookieName ."'>";
    $script .= '<script type="text/javascript" src="' .CSRFP_SELF .CSRFP_JS .'"></script>';	

    //implant the CSRFGuard js file to outgoing script
    $buffer = str_ireplace('</body>', $script . '</body>', $buffer, $count);
    if (!$count) {
        $buffer .= $script;
    }

    return $buffer;
}


// Initialize our handler
ob_start('csrf_ob_handler');	//#todo: feature to not run this when required

