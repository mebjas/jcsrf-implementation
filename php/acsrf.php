<?php
/** 
 * php library to mitigate CSRF 
 * inspire form OWASP
 */

//assuming $_POST to be always set
if( count($_POST) && !isset($_POST['CSRFtoken']))
{
	/**
	 * if CSRFtoken does not exists unset all existing POST entries 
	 */
	unset($_POST);
}

if( isset($_POST['CSRFtoken']) && isset($_COOKIE['CSRFtoken']) && ( $_POST['CSRFtoken'] != $_COOKIE['CSRFtoken'] ) )
{
	/**
	 * if CSRFtoken does not match unset all POST entries
	 */
	unset($_POST);
}


/** 
 * class containing all values and methods for Anti CSRF library
 */
class acsrf
{

}


