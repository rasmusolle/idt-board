<?php
$start = microtime(true);

require "config.php";

$tags_search = [
	"/\\r\\n?/",
	"/\\n/",
	"/\\t/",
	"/\[url\=(.*?)\](.*?)\[\/url\]/i",
	"/\[img\=(.*?)\]/i",
	"/\[i\](.*?)\[\/i\]/i",
	"/\[u\](.*?)\[\/u\]/i",
	"/\[b\](.*?)\[\/b\]/i",
	"/\[em\](.*?)\[\/em\]/i",
	"/\[small\](.*?)\[\/small\]/i",
	"/&amp;#([0-9]*);/i", // don't destroy unicode
];

$tags_replace = [
	"<br>", "<br>",
	"&nbsp;&nbsp;&nbsp;&nbsp;",
	"<a href=\"\\1\">\\2</a>",
	"<img src=\"\\1\">",
	"<i>\\1</i>",
	"<u>\\1</u>",
	"<b>\\1</b>",
	"<em>\\1</em>",
	"<small>\\1</small>",
	"&#\\1;",
];

$tags_decode_search = [
	"/<br>/",
	"/&nbsp;&nbsp;&nbsp;&nbsp;/",
	"/<a href\=\\\"(.*?)\\\">(.*?)<\/a>/",
	"/<img src=\\\"(.*?)\\\">/",
	"/<i>(.*?)<\/i>/",
	"/<u>(.*?)<\/u>/",
	"/<b>(.*?)<\/b>/",
	"/<em>(.*?)<\/em>/",
	"/<small>(.*?)<\/small>/",
];

$tags_decode_replace = [
	"\n",
	"\t",
	"[url=\\1]\\2[/url]",
	"[img=\\1]",
	"[i]\\1[/i]",
	"[u]\\1[/u]",
	"[b]\\1[/b]",
	"[em]\\1[/em]",
	"[small]\\1[/small]",
];

function pageheader($title = NULL) {
	global $cookie_uname, $cookie_token, $my_path, $messages;

	echo "<html><head>";
	echo '<meta name="viewport" content="width=device-width, initial-scale=1">';

	echo "<title>Forum - ";
	if (is_null($title)) {
		echo $messages[rand(0, count($messages) - 1)];
	} else {
		echo $title;
	}

	echo "</title>";
	?>
<link rel="stylesheet" type="text/css" href="forum.css">
</head><body>
<div class="content center">
	<a href="<?=$my_path ?>">Main</a> |
	<a href="<?=$my_path ?>?memberlist">Memberlist</a>
	<br><br>
	<?php
	if (!isset($_COOKIE[$cookie_uname]) || !isset($_COOKIE[$cookie_token])) {
		$userlinks[] = ['page' => 'login', 'title' => 'Login'];
		$userlinks[] = ['page' => 'adduser', 'title' => 'Register'];
	} else {
		$userlinks[] = ['page' => 'logout', 'title' => 'Logout'];
		$userlinks[] = ['page' => 'chpass', 'title' => 'Change Password'];
		$userlinks[] = ['page' => 'newthread', 'title' => 'New Thread'];
	}
	$c = 0;
	foreach ($userlinks as $k => $v) {
		if ($c > 0) echo " | ";
		echo "<a href=\"$my_path?{$v['page']}\">{$v['title']}</a>";
		$c++;
	}
	?>
</div><br>
<?php
}

function NewPostForm($threadid) {
	global $cookie_uname, $cookie_token, $full_path;
	?>
<div class="content">
	<form action="<?=$full_path ?>?addpost" method="POST"><table class="postform">
		<tr><td class="formcaption">Subject<td><input type="text" name="subject" size="45"></tr>
		<tr><td class="formcaption">Message<td><textarea name="message" rows="10" cols="50"></textarea>
		<tr><td align="center" colspan="2"><input type="submit" value="Submit"></td></tr>
	</table><input type="hidden" name="inresponseto" value="<?=$threadid ?>"></form>
</div><?php
}

function EditPostForm($postid, $content, $subject) {
	global $cookie_uname, $cookie_token, $full_path;
	?>
<div class="content">
	<form action="<?=$full_path ?>?editpost2" method="POST"><table class="postform">
		<tr><td class="formcaption">Subject<td><input type="text" name="subject" size="45" value="<?=$subject ?>"></tr>
		<tr><td class="formcaption">Message<td><textarea name="message" rows="10" cols="50"><?=$content ?></textarea>
		<tr><td align="center" colspan="2"><input type="submit" value="Submit"></td></tr>
	</table><input type="hidden" name="posttoupdate" value="<?=$postid ?>"></form>
</div><?php
}

// authenticate by user name/pass or by cookies
// return user id, die if authentication fails
function authenticate($use_cookies, $user = null, $pass = null) {
	global $cookie_uname, $cookie_token;
	if (isset($user) && $user != '' && isset($pass) && $pass != '') {
		$query = fetch("SELECT idx, pass_hash FROM users WHERE uname = ?", [$user]);

		if (!password_verify($pass, $query['pass_hash'])) die("Authentication failed.");
	} else if ($use_cookies && isset($_COOKIE[$cookie_uname]) && isset($_COOKIE[$cookie_token])) {
		$query = fetch("SELECT idx FROM users WHERE uname = ? AND logintoken = ?", [$_COOKIE[$cookie_uname], $_COOKIE[$cookie_token]]);

		if ($query == null) {
			die("Authentication failed");
		}
	} else {
		die("Authentication failed (incomplete data).");
	}

	return $query['idx'];
}

// update the last updated timestamp for a post/thread
function update_post_time($idx) {
	query("UPDATE board SET lasttime = NOW() WHERE idx = ? LIMIT 1", [$idx]);
}

// MYSQL
$options = [
	PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
	PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
	PDO::ATTR_EMULATE_PREPARES   => false,
];
try {
	$sql = new PDO("mysql:host=$host;dbname=$db;charset=utf8mb4", $user, $pass, $options);
} catch (\PDOException $e) {
	if (function_exists('fs_error'))
		fs_error('Database error 1F');
	else
		die('Database error 1F');
}

function query($query,$params = []) {
	global $sql;

	$res = $sql->prepare($query);
	$res->execute($params);
	return $res;
}

function fetch($query,$params = []) {
	global $sql;

	$res = query($query,$params);
	return $res->fetch();
}

function result($query,$params = []) {
	global $sql;

	$res = query($query,$params);
	return $res->fetchColumn();
}

// ***************************** Top of code ********************************

if (isset($_GET['login'])) { // **** Display login form
	pageheader();
	?>
<div class="content"><form action="<?php echo $full_path; ?>?login2" method="POST"><table>
	<tr><td>Username</td><td><input type="text" name="uname" maxlength="31"></td></tr>
	<tr><td>Password</td><td><input type="password" name="pass" maxlength="31"></td></tr>
	<tr><td align="center" colspan="2"><input type="submit" value="Submit"></td></tr>
</table></form></div>
	<?php
} else if (isset($_GET['login2'])) { // **** Process login
	if (result("SELECT COUNT(*) FROM users WHERE uname = ?", [$_POST['uname']]) != 1) die("User doesn't exist.");

	$userdata = fetch("SELECT idx, pass_hash, lastlogin, UNIX_TIMESTAMP(lastlogin) AS llstamp FROM users WHERE uname=?", [$_POST['uname']]);

	if (!password_verify($_POST['pass'], $userdata['pass_hash'])) die("Authentication failed.");

	if (!isset($_COOKIE[$cookie_uname]) || !isset($_COOKIE[$cookie_token])) {
		//$newid = md5(uniqid(rand(), true));
		$newid = bin2hex(random_bytes(16));
		setcookie($cookie_uname, $_POST['uname'], time() + $cookie_expire);
		setcookie($cookie_token, $newid, time() + $cookie_expire);

		// store cookie in db
		query("UPDATE users SET logintoken=?, lastlogin=NOW(), prevlogin=? WHERE idx=?", [$newid, $lastlogin, $userdata['idx']]);
	} else {
		// update cookie
		setcookie($cookie_uname, $_COOKIE[$cookie_uname], time() + $cookie_expire);
		setcookie($cookie_token, $_COOKIE[$cookie_token], time() + $cookie_expire);

		// store cookie in db
		query("UPDATE users SET lastlogin = NOW(), prevlogin = ? WHERE idx = ?", [$lastlogin, $uid]);
	}
	header("Location: $my_path");
} else if (isset($_GET['logout'])) { // Log Out
	setcookie($cookie_uname, "", time() - 3600);
	setcookie($cookie_token, "", time() - 3600);

	if (isset($_COOKIE[$cookie_uname])) {
		query("UPDATE users SET logintoken = NULL, lastlogin = NOW() WHERE uname = ? AND logintoken = ?", [$_COOKIE[$cookie_uname], $_COOKIE[$cookie_token]]);
	}

	header("Location: $my_path");
} else if (isset($_GET['adduser'])) { // **** Display form to add a user
	pageheader();
	?>
<div class="content"><form action="<?php echo $full_path; ?>?adduser2" method="POST"><table>
	<tr><td>Username</td><td><input type="text" name="uname" maxlength="31"></td></tr>
	<tr><td>Password</td><td><input type="password" name="pass" maxlength="31"></td></tr>
	<tr><td>Verify Password</td><td><input type="password" name="vpass" maxlength="31"></td></tr>
	<tr><td align="center" colspan="2"><input type="submit" value="Submit"></td></tr>
</table></form></div><?php
} else if (isset($_GET['adduser2'])) { // **** Add a user to the database
	pageheader();

	if (htmlspecialchars($_POST['uname'], ENT_QUOTES) != $_POST['uname']) die("Avoid special characters (&lt;, &gt;, &#039, &quot;) in user name ");

	// check if user already exists
	if (result("SELECT COUNT(*) FROM users WHERE uname = ?", [$_POST['uname']]) == 0) {
		if ($_POST['pass'] == $_POST['vpass']) {
			if ($_POST['pass'] == '' || $_POST['pass'][strlen($_POST['pass']) - 1] == '!') die("Please fill in all the fields.");

			$pass_hash = password_hash($_POST['pass'], PASSWORD_BCRYPT, ['cost' => 10]);
			query("INSERT INTO users SET idx=NULL, joined=NOW(), uname=?, pass_hash=?", [$_POST['uname'], $pass_hash]);

			header("Location: $my_path");
		} else {
			echo "the passwords did not match";
		}
	} else {
		echo "User name $_POST[uname] already exists.";
	}

} else if (isset($_GET['userinfo'])) { // **** User info page
	if (result("SELECT COUNT(*) FROM users WHERE idx = ?", [$_GET['userinfo']]) != 1) die("This user doesn't exist!");

	// get info from users database
	$userdata = fetch("SELECT uname, UNIX_TIMESTAMP(joined) as joindate, logintoken, UNIX_TIMESTAMP(lastlogin), postcount as login FROM users WHERE idx = ?", [$_GET['userinfo']]);

	pageheader($userdata['uname'] . " user info");

	echo "<div class=\"content\"><strong>Info for user {$userdata['uname']}:</strong><br><br>";
	echo "Joined: " . date("$datefmt $timefmt", $userdata['joindate']) . "<br>";
	echo "Posts: " . $userdata['postcount'] . "<br>";

	//if ($userdata2['postcount'] > 0) {
	//	echo "Last post " . date("$datefmt $timefmt", $userdata2['lasttime']) . "<br>";
	//}

	if (isset($userdata['logintoken']) && $userdata['logintoken'] != "") {
		echo "Logged in " . date("$datefmt $timefmt", $userdata['login']) . "<br>";
	} else if ($userdata['login'] > 0) {
		echo "Last logged in " . date("$datefmt $timefmt", $userdata['login']) . "<br>";
	} else {
		echo "Never logged in.<br>";
	}

	echo "</div>";
} else if (isset($_GET['memberlist'])) { // **** User list
	pageheader("Memberlist");

	$query = query("SELECT uname, UNIX_TIMESTAMP(joined) joined, postcount, idx AS uid FROM users ORDER BY postcount DESC");

	echo "<table class=\"userlist\"><tr><th colspan=4>Memberlist</th></tr><tr class=\"center\"><td>Name</td><td width=70>Posts</td><td width=120>Joined</td></tr>";
	while ($record = $query->fetch()) {
		echo "<tr class=\"center\"><td class=\"name left\"><a href=\"$my_path?userinfo={$record['uid']}\">{$record['uname']}</a></td><td>{$record['postcount']}</td><td>" . date("$datefmt $timefmt", $record['joined']) . "</td></tr>";
	}
	echo "</table>";
} else if (isset($_GET['chpass'])) { // **** Change password form
	pageheader();
	if (!isset($_COOKIE[$cookie_uname]) && !isset($_COOKIE[$cookie_token])) die('You need to login!');
	?>
<div class="content">
	<b>Change Password</b><br>
	<form action="<?=$full_path; ?>?chpass2" method="POST"><table>
	<tr><td>Old Password<td><input type="password" name="oldpass" maxlength="31"></tr>
	<tr><td>New Password<td><input type="password" name="newpass" maxlength="31"></tr>
	<tr><td>Verify New Password<td><input type="password" name="vnewpass" maxlength="31"></tr>
	<tr><td align="center" colspan="2"><input type="submit" value="Submit"></tr>
	</table></form>
</div>
	<?php
} else if (isset($_GET['chpass2'])) { // **** Set new password
	if ($_POST['newpass'] != $_POST['vnewpass']) die("The passwords aren't the same!");
	if ($_POST['newpass'] == '') die("You can't have a blank password!");

	$newpass_hash = password_hash($_POST['newpass'], PASSWORD_BCRYPT, ['cost' => 10]);
	$uid = authenticate(false, $_POST['uname'], $_POST['oldpass']);
	query("UPDATE users SET pass_hash = ? WHERE idx = ? AND uname = ? LIMIT 1", [$newpass_hash, $uid, $_POST['uname']]);

	header("Location: $my_path");
} else if (isset($_GET['newthread'])) {
	pageheader();
	NewPostForm(0);
} else if (isset($_GET['showthread'])) { // **** Show a single thread
	// put thread subject in title
	$subject = result("SELECT subject FROM board WHERE idx = ?", [$_GET['showthread']]);
	//mysqli_stmt_fetch($query) or die("no such post found" . mysqli_error($dbh));
	pageheader($subject);

	// count posts in thread
	$postcount = result("SELECT COUNT(*) FROM board WHERE board.replyto = ? OR board.idx = ?", [$_GET['showthread'], $_GET['showthread']]);

	$pageno = (isset($_GET['showpage']) ? $_GET['showpage'] : null);
	$lastpage = floor(($postcount - 1) / $postsperpage);
	if (isset($_GET['lastpage'])) {
		$pageno = $lastpage;
	}

	$firstonpage = $pageno * $postsperpage;

	// get user's last login time
	if (isset($_COOKIE[$cookie_uname]) && isset($_COOKIE[$cookie_token])) {
		$lastlogin = result("SELECT UNIX_TIMESTAMP(prevlogin) AS llstamp FROM users WHERE uname = ?", [$_COOKIE[$cookie_uname]]);

		if ($lastlogin == null) $lastlogin = 0;
	} else {
		$lastlogin = 0;
	}

	$query = query("
SELECT board.subject AS subject, board.message AS message, board.idx AS message_id, UNIX_TIMESTAMP(board.postedtime) AS postedtime, UNIX_TIMESTAMP(board.lasttime) AS updatetime, users.uname AS uname, users.idx AS uid
FROM board, users WHERE board.author = users.idx AND (board.replyto = ? OR board.idx = ?) ORDER BY postedtime ASC LIMIT ?,?",
	[$_GET['showthread'], $_GET['showthread'], $firstonpage, $postsperpage]);

	echo "<div class=\"postlist\">\n";
	while ($record = $query->fetch()) {
		echo "<div class=\"content\" id=\"post_{$record['message_id']}\"><span class=\"subject\">";
		if ($lastlogin > 0 && $record['updatetime'] > $lastlogin) echo "* ";
		echo "{$record['subject']}</span> by <span class=\"name\"><a href=\"$my_path?userinfo={$record['uid']}\">{$record['uname']}</a></span> at " . date("$datefmt $timefmt", $record['postedtime']) . "</div>\n";
		echo "<div class=\"content\" style=\"border-top:0px\">".$record['message'];
		if ((!isset($_COOKIE[$cookie_uname]) || !isset($_COOKIE[$cookie_token])) || !strcmp($record['uname'], $_COOKIE[$cookie_uname])) {
			echo "<br><small><a href=\"$my_path?editpost={$record['message_id']}\">[edit]</a></small>";
		}
		echo "</div><br>\n";
	}
	echo "</div>Go to Page ";
	for ($i = 0; $i <= $lastpage; $i++) {
		if ($pageno != $i) echo "<a href=\"$my_path?showthread=" . $_GET['showthread'] . "&showpage=$i\">";
		echo "$i";
		if ($pageno != $i) echo "</a>";
		echo " ";
	}
	echo "<br><br>";

	NewPostForm($_GET['showthread']);
} else if (isset($_GET['addpost'])) { // **** Add a post
	pageheader();

	$uid = authenticate(true);

	if ($_POST['inresponseto'] == "0" && (!isset($_POST['subject']) || $_POST['subject'] == "" || ctype_space($_POST['subject']))) die("Cannot start thread with empty subject.");
	if ((!isset($_POST['message']) || $_POST['message'] == "" || ctype_space($_POST['message']))) die("Please type a message for your post.");

	query("INSERT INTO board VALUES(NULL,NOW(),NOW(),?,?,?,?,?)",
		[$uid, $_POST['inresponseto'], htmlspecialchars($_POST['subject'], ENT_QUOTES), preg_replace($tags_search, $tags_replace, htmlspecialchars($_POST['message'], ENT_QUOTES)), $_SERVER['REMOTE_ADDR']]);
		
	query("UPDATE users SET postcount = postcount + 1 WHERE idx = 1");

	// update thread last updated time
	if ($_POST['inresponseto'] != 0) {
		update_post_time($_POST['inresponseto']);
		header("Location: $my_path?showthread={$_POST['inresponseto']}&lastpage");
	}
	header("Location: $my_path?showthreads");
} else if (isset($_GET['editpost'])) { // **** Display post edit form
	pageheader();

	$post = fetch("SELECT subject,message FROM board WHERE idx = ?", [$_GET['editpost']]);

	if ($post == null) die("Post doesn't exist.");

	EditPostForm($_GET['editpost'], preg_replace($tags_decode_search, $tags_decode_replace, $post['message']), $post['subject']);
} else if (isset($_GET['editpost2'])) { // **** Commit an edited post
	$posttoedit = intval($_POST['posttoupdate']);

	// look up what post this reponds to and when it was first posted
	$thread = fetch("SELECT replyto, UNIX_TIMESTAMP(postedtime) FROM board WHERE idx = ? LIMIT 1", [$_POST['posttoupdate']]);

	if ($thread == null) die("Couldn't find thread.");

	$uid = authenticate(true);

	if ($query['replyto'] == "0" && (!isset($_POST['subject']) || $_POST['subject'] == "" || ctype_space($_POST['subject']))) {
		die("Thread cannot have empty subject");
	}

	if ((!isset($_POST['message']) || $_POST['message'] == "" || ctype_space($_POST['message']))) {
		die("empty message not allowed!");
	}

	$message = preg_replace($tags_search,$tags_replace,htmlspecialchars($_POST['message'],ENT_QUOTES))."<br><br><small><i>edited ".date("$datefmt $timefmt")."</i></small>";
	query("UPDATE board SET subject = ?, message = ?, ip = ?, lasttime = NOW() WHERE idx = ? AND author = ? LIMIT 1",
		[htmlspecialchars($_POST['subject'], ENT_QUOTES), $message, $_SERVER['REMOTE_ADDR'], $_POST['posttoupdate'], $uid]);

	update_post_time($thread['replyto']);
	header("Location: $my_path?showthread={$thread['replyto']}");
} else { // **** Display Threads
	pageheader();

	// get user's last login time
	if (isset($_COOKIE[$cookie_uname]) && isset($_COOKIE[$cookie_token])) {
		// login time
		$query = fetch("SELECT UNIX_TIMESTAMP(prevlogin) AS llstamp FROM users WHERE uname = ?", [$_COOKIE[$cookie_uname]]);

		if (isset($query['llstamp'])) {
			$lastlogin = $query['llstamp'];
		} else {
			$lastlogin = 0;
		}
	} else {
		$lastlogin = 0;
	}

	// first page has count($pinned_threads) + $threadsperpage,
	// subsequent pages have $threadsperpage
	$pagenumber = (isset($_GET['showpage']) ? $_GET['showpage'] : null);

	if ($pagenumber == 0) {
		$firstonpage = 0;
		$threadsonthispage = count($pinned_threads) + $threadsperpage;
	} else {
		$firstonpage = count($pinned_threads) + $threadsperpage * $pagenumber;
		$threadsonthispage = $threadsperpage;
	}

	// thread list
	$pinned_threads_sql = "idx IN ('" . join($pinned_threads, "','") . "') AS pinned,";

	$query_str = 
"SELECT
	pinned,
	b1.idx AS threadid,
	subject,
	UNIX_TIMESTAMP(lasttime) AS lasttime,
	(SELECT 1+COUNT(*) FROM board WHERE replyto = threadid) AS postcount,
	IFNULL(lastreply, b1.idx) AS lastpost,
	(SELECT author FROM board WHERE idx = lastpost) AS lastuid,
	(SELECT uname FROM users WHERE idx = lastuid) AS lastuname
FROM (SELECT
	$pinned_threads_sql
	idx,
	(SELECT idx FROM board WHERE replyto = b0.idx ORDER BY postedtime DESC LIMIT 1) AS lastreply
	FROM board b0
	WHERE replyto = '0'
	ORDER BY pinned DESC, lasttime DESC
	LIMIT ?,?) b1
JOIN board b2
ON b1.idx = b2.idx";

	$query = query($query_str, [$firstonpage, $threadsonthispage]);

	// get thread list
	echo "<table class=\"threadlist\">
<tr><th colspan=4>Threads</th></tr>
<tr class=\"center\"><td>Subject</td><td width=70>Posts</td><td width=125>Last updated</td></tr>";

	$saw_pinned = 0;

	while ($thread = $query->fetch()) {
		if (!$thread['pinned'] && $saw_pinned) {
			$saw_pinned = 0;
			echo "<tr><td colspan=4>&nbsp;</td></tr>\n";
		}
		echo "<tr class=\"center\">\n<td class=\"left\"><span class=\"subject\">";
		if ($lastlogin > 0 && isset($thread['thread_lasttime']) && $thread['thread_lasttime'] > $lastlogin) {
			echo "* ";
		}

		echo "<a href=\"$my_path?showthread={$thread['threadid']}\">{$thread['subject']}</a>";
		if ($thread['pinned']) {
			$saw_pinned = 1;
			echo " <small>(pin'd)</small>";
		}
		$lastpage = 0;
		if ($thread['postcount'] > $postsperpage) {
			$lastpage = floor(($thread['postcount'] - 1) / $postsperpage);
			echo " <small><a href=\"$my_path?showthread={$thread['threadid']}&lastpage\">(last page)</a></small>";
		}
		echo "</span></td>
<td>{$thread['postcount']}</td>
<td><a href=\"$my_path?showthread={$thread['threadid']}&showpage=$lastpage#post_{$thread['lastpost']}\">" . date($datefmt . " " . $timefmt, $thread['lasttime']) . "</a><br>
by <span class=\"name\"><a href=\"$my_path?userinfo={$thread['lastuid']}\">{$thread['lastuname']}</a></span></td>
</tr>\n";
	}

	echo "</table>\n";

	$count = result("SELECT COUNT(*) FROM board WHERE replyto = '0'");
	
	$showprev = ($pagenumber > 0);
	$shownext = ($firstonpage + $threadsonthispage < $count);

	if ($showprev || $shownext) {
		echo "<br>";
		if ($showprev) echo "<a href=\"$my_path?showthreads&showpage=".($pagenumber - 1)."\">Previous Page</a>";
		if ($showprev && $shownext) echo " | ";
		if ($shownext) echo "<a href=\"$my_path?showthreads&showpage=".($pagenumber + 1)."\">Next Page</a>";
		echo "<br>";
	}
}

?><br>
<div class="content center">
<?php
$rendertime = microtime(true) - $start;
echo sprintf("Page rendered in %1.3f seconds using %dKB of memory", $rendertime, memory_get_usage(false) / 1024);
?>
</div>
</body></html>