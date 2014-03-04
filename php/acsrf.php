<?php
/** 
 * php library to mitigate CSRF 
 * inspire form OWASP
 * Uses token based mitigation techniques for CSRF prevention!
 */

/**
 * if CSRFtoken does not exists unset all existing POST entries 
 */
if( count($_POST) && !isset($_POST['CSRFtoken']))
{
	//@todo: log the request data to db
	unset($_POST);
}

/**
 * if CSRFtoken does not match unset all POST entries
 */
if( isset($_POST['CSRFtoken']) && isset($_COOKIE['CSRFtoken']) && ( $_POST['CSRFtoken'] != $_COOKIE['CSRFtoken'] ) )
{
	//@todo: log th request and alert the user
	unset($_POST);
}


/** 
 * class containing all values and methods for Anti CSRF library
 */
class acsrf
{
	//list of whitelisted website 
	private $whitelist = array();


	/**
	 * function to generate pseudo random code
	 */
	public static function getKey($unique_form_name)
	{
		if (function_exists("hash_algos") and in_array("sha512",hash_algos()))
		{
			$token  =hash("sha512",uniqid() .mt_rand(0,mt_getrandmax()));
		}
		else
		{
			$token = ' ';
			for ($i = 0; $i < 128; ++$i)
			{
				$r = mt_rand(0,35);
				if ($r<26)
				{
					$c = chr(ord('a')+$r);
				}
				else
				{ 
					$c = chr(ord('0')+$r-26);
				} 
				$token .= $c;
			}
		}
		return $token;
	}

	/**
	 * function to return encrypted package for cross-site requests
	 */
	public static function csrf_encrypt($domain,$token)
	{
		return convert_uuencode($token ."_" .$token);
	}

	/**
	 * function to return decrypted data in array
	 */
	public static function csrf_decrypt($hash)
	{
		return explode("_",convert_uudecode($hash));
	}
}


