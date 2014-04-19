<?php

include_once __DIR__ .'/libs/csrf.php';


csrfGuard::authorisePost();


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

    $script = '<script type="text/javascript">CsrfMagic.end();</script>';
    $buffer = str_ireplace('</body>', $script . '</body>', $buffer, $count);
    if (!$count) {
        $buffer .= $script;
    }
    
    return $buffer;
}