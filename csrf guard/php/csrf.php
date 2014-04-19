<?php
namespace csrfGuard;

class csrfGuard
{
	/**
	 * Name of the cookie sent to client
	 */
	public static $cookieName = 'CSRF_AUTH_TOKEN';

	/**
	 * Name of the POST variable sent from client
	 */
	public static $postName = 'CSRF_AUTH_TOKEN';

	/**
	 * expiry time for cookie
	 */
	public static $cookieExpiryTime = 300;	//5 minutes
	
	/**
	 * function to authorise incoming post requests
	 */
	public static function authorisePost()
	{
		if(isset($_POST)) {
			if(isset($_POST[csrfGuard::$postName]) 
				&& isset($_COOKIE[csrfGuard::$cookieName])
				&& ($_POST[csrfGuard::$postName] === $_COOKIE[csrfGuard::$cookieName])
				) {
				csrfGuard::refreshCookie();		
			}
		}
	}

	/**
	 * function to refresh cookie sent to browser
	 */
	public static function refreshCookie()
	{
		if(!isset($_COOKIE[csrfGuard::$cookieName])) {
			csrfGuard::createCookie();
		} else {
			//reset the cookie to a longer period
			setcookie(csrfGuard::$cookieName, $_COOKIE[csrfGuard::$cookieName], time() + csrfGuard::$cookieExpiryTime);
		}
	}

	/**
	 * 
	 */
	public static function createCookie()
	{
		setcookie(csrfGuard::$cookieName, csrfGuard::generateAuthToken(128), time() + csrfGuard::$cookieExpiryTime);
	}

	/**
	 * function to generate random hash of length as given in parameter
	 * max length = 128
	 * @param: length to hash required, int
	 */
	public static function generateAuthToken($length = 128)
	{
		//if $length > 128 throw exception #todo 

		if (function_exists("hash_algos") && in_array("sha512", hash_algos())) {
			$token = hash("sha512", mt_rand(0, mt_getrandmax()));
		} else {
			$token=' ';
			for ($i=0;$i<128;++$i)
			{
				$r=mt_rand(0,35);
				if ($r<26)
				{
					$c=chr(ord('a')+$r);
				}
				else
				{ 
					$c=chr(ord('0')+$r-26);
				} 
				$token.=$c;
			}
		}
		return substr($token, 0, $length);
	}
};

