<?php

include_once __DIR__ .'/config/csrf.config.inc.php';
include_once __DIR__ .'/libs/csrf.php';

//Initialise CSRFGuard library
csrfGuard::initialise();

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

    if(CSRFGuard::$isSameOrigin) {
    	$script = '<script type="text/javascript" src="' .CSRF_SELF .SAME_ORIGIN_JS .'"></script>';	
    } else {
    	$script = '<script type="text/javascript" src="' .CSRF_SELF .CROSS_ORIGIN_JS .'"></script>';
    }

    //implant the CSRFGuard js file to outgoing script
    $buffer = str_ireplace('</body>', $script . '</body>', $buffer, $count);
    if (!$count) {
        $buffer .= $script;
    }

    return $buffer;
}


// Initialize our handler
	ob_start('csrf_ob_handler');	//#todo: feature to not run this when required

