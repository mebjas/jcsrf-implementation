<?php

	include '../../php/acsrf.php';
	foreach ($_POST as $key => $value) {
		echo "$key = $value <br>";
	}
?>

<!DOCTYPE html>
<html>
<head>
<title>testing csrf prevention</title>


<body>
<form action="index.php" method="post">
	<input type="text" name="username" id="username" placeholder="username" value=""><br>
	<input type="text" name="password" id="password" placeholder="password" value=""><br>
	<input type="text" name="pin" id="pin" placeholder="pin" value=""><br>
	<input type="submit" name="submit" value="submit">
</form>

<form action="index.php" method="post">
	<input type="text" name="username" id="username" placeholder="username" value=""><br>
	<input type="text" name="password" id="password" placeholder="password" value=""><br>
	<input type="text" name="pin" id="pin" placeholder="pin" value=""><br>
	<input type="submit" name="submit" value="submit">
</form>
<form action="index.php" method="post">
	<input type="text" name="username" id="username" placeholder="username" value=""><br>
	<input type="text" name="password" id="password" placeholder="password" value=""><br>
	<input type="text" name="pin" id="pin" placeholder="pin" value=""><br>
	<input type="submit" name="submit" value="submit">
</form>
<form action="index.php" method="post">
	<input type="text" name="username" id="username" placeholder="username" value=""><br>
	<input type="text" name="password" id="password" placeholder="password" value=""><br>
	<input type="text" name="pin" id="pin" placeholder="pin" value=""><br>
	<input type="submit" name="submit" value="submit">
</form>
</body>
<?php
	$csrfguardObj->injectScript();
?>
</head>
</html>