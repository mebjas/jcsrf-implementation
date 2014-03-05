<?php
/** 
 * php library to mitigate CSRF 
 * inspire form OWASP
 * Uses token based mitigation techniques for CSRF prevention!
 */
var_dump($_POST);
define("cookie_name","CSRF_AUTH_TOKEN");


/** 
 * class containing all values and methods for Anti CSRF library
 */
class acsrf
{
	//list of whitelisted website 
	private $whitelist = array();

	//autherisation key
	private $key;

	/**
	 * constructor
	 */
	function __construct($key = null)
	{
		if($key == null)
		{
			$this->generateKey();
		}
		else $this->key = $key;
	}
	/**
	 * function to generate pseudo random code
	 */
	public function generateKey()
	{
		if (function_exists("hash_algos") and in_array("sha512",hash_algos()))
		{
			$this->key = hash("sha512",uniqid() .mt_rand(0,mt_getrandmax()));
		}
		else
		{
			$this->key = ' ';
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
				$this->key .= $c;
			}
		}
	}

	/**
	 * function to get key
	 */
	public function getKey()
	{
		return $this->key;
	}

	/**
	 * function to get key
	 */
	public function setKeyToCookie()
	{
		setcookie(cookie_name,$this->key,time()+1000);
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

	/**
	 * function to print script to page
	 */
	public function injectScript()
	{
		echo "<script>";
		echo "
		var forms = document.getElementsByTagName('form');
		/*
		for(i=0;i<forms.length;i++)
		{
			forms[i].addEventListener('submit', function(e) {
				var obj = e.srcElement ? e.srcElement : e.target;
				console.log(obj);
				obj.innerHTML += '<input type=\"hidden\" name=\"" .cookie_name."\" id=\"" .cookie_name."\" value=\"'+getCookie('".cookie_name."')+'\">';
				obj.submit();
        		e.preventDefault();
   				return false;
			}, false);
		}
		*/
		function getCookie(cname)
		{
		var name = cname + \"=\";
		var ca = document.cookie.split(';');
		for(var i=0; i<ca.length; i++) 
		  {
		  var c = ca[i].trim();
		  if (c.indexOf(name)==0) return c.substring(name.length,c.length);
		}
		return \"\";
		}
		for(i=0;i<forms.length;i++)
		{
			forms[i].innerHTML += '<input type=\"hidden\" name=\"" .cookie_name."\" id=\"" .cookie_name."\" value=\"'+getCookie('".cookie_name."')+'\">';
		}		


		";
		echo "</script>";
	}

}

/**
 * if CSRFtoken does not exists unset all existing POST entries 
 */
if(!isset($_POST[cookie_name]))
{
	//@todo: log the request data to db
	foreach($_POST as $key => $values)
		unset($_POST[$key]);
	$csrfguardObj = new acsrf();
	$csrfguardObj->setKeyToCookie();
}
else if(( isset($_POST[cookie_name]) && 
	isset($_COOKIE[cookie_name]) ) && 
	( $_POST[cookie_name] != $_COOKIE[cookie_name] ))
{
	//@todo: log the request data to db
	foreach($_POST as $key => $values)
		unset($_POST[$key]);
	$csrfguardObj = new acsrf();
	$csrfguardObj->setKeyToCookie();
}
else
{
	$csrfguardObj = new acsrf($_COOKIE[cookie_name]);
	$csrfguardObj->setKeyToCookie();
}
