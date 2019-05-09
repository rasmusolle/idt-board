<?php
$start = microtime(true);

require "config.php";

$tags['s'] = [
	"/\\r\\n?/", "/\\n/",
	"/\[b\](.*?)\[\/b\]/i", "/\[i\](.*?)\[\/i\]/i", "/\[u\](.*?)\[\/u\]/i",
	"/\[url\=(.*?)\](.*?)\[\/url\]/i",
	"/\[img\=(.*?)\]/i",
	"/&amp;#([0-9]*);/i"
];
$tags['r'] = [
	"<br>", "<br>",
	"<b>\\1</b>", "<i>\\1</i>", "<u>\\1</u>",
	"<a href=\"\\1\">\\2</a>",
	"<img src=\"\\1\">",
	"&#\\1;"
];

$tags_decode['s'] = [
	"/<br>/",
	"/<b>(.*?)<\/b>/", "/<i>(.*?)<\/i>/", "/<u>(.*?)<\/u>/",
	"/<a href\=\\\"(.*?)\\\">(.*?)<\/a>/",
	"/<img src=\\\"(.*?)\\\">/",
];
$tags_decode['r'] = [
	"\n",
	"[b]\\1[/b]", "[i]\\1[/i]", "[u]\\1[/u]",
	"[url=\\1]\\2[/url]",
	"[img=\\1]",
];

function pageheader($title = null) {
	global $messages;
	?>
<html><head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<link rel="stylesheet" type="text/css" href="forum.css">
	<title>Forum - <?=(is_null($title) ? $messages[rand(0, count($messages) - 1)] : $title) ?></title>
</head><body>
<div class="content center">
	<a href="./">Main</a> |
	<a href="?memberlist">Memberlist</a>
	<br><br>
	<?php
	if (!isset($_COOKIE['idt-user']) || !isset($_COOKIE['idt-token'])) {
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
		echo "<a href=\"?{$v['page']}\">{$v['title']}</a>";
		$c++;
	}
	?>
</div><br><?php
}

function pagefooter() {
	global $start;
	$rendertime = microtime(true) - $start;
	?>
<br><div class="content center">
<?=sprintf("Page rendered in %1.3f seconds using %dKB of memory", $rendertime, memory_get_usage(false) / 1024) ?>
</div>
</body></html><?php
}

function NewPostForm($threadid) {
	?>
<div class="content">
	<form action="?addpost" method="POST"><table class="postform">
		<tr><td class="formcaption">Subject<td><input type="text" name="subject" size="45"></tr>
		<tr><td class="formcaption">Message<td><textarea name="message" rows="10" cols="50"></textarea>
		<tr><td align="center" colspan="2"><input type="submit" value="Submit"></td></tr>
	</table><input type="hidden" name="inresponseto" value="<?=$threadid ?>"></form>
</div><?php
}

function EditPostForm($postid, $content, $subject) {
	?>
<div class="content">
	<form action="?editpost2" method="POST"><table class="postform">
		<tr><td class="formcaption">Subject<td><input type="text" name="subject" size="45" value="<?=$subject ?>"></tr>
		<tr><td class="formcaption">Message<td><textarea name="message" rows="10" cols="50"><?=$content ?></textarea>
		<tr><td align="center" colspan="2"><input type="submit" value="Submit"></td></tr>
	</table><input type="hidden" name="posttoupdate" value="<?=$postid ?>"></form>
</div><?php
}

// authenticate by user name/pass or by cookies
// return user id, die if authentication fails
function authenticate($use_cookies, $user = null, $pass = null) {
	if (isset($user) && $user != '' && isset($pass) && $pass != '') {
		$query = fetch("SELECT idx, pass_hash FROM users WHERE uname = ?", [$user]);

		if (!password_verify($pass, $query['pass_hash'])) error("Authentication failed.");
	} else if ($use_cookies && isset($_COOKIE['idt-user']) && isset($_COOKIE['idt-token'])) {
		$query = fetch("SELECT idx FROM users WHERE uname = ? AND logintoken = ?", [$_COOKIE['idt-user'], $_COOKIE['idt-token']]);

		if ($query == null) {
			error("Authentication failed");
		}
	} else {
		error("Authentication failed (incomplete data).");
	}

	return $query['idx'];
}

function error($msg) {
	pageheader('Error');
	echo '<div class="content center"><strong>Error</strong><br>'.$msg.'</div>';
	pagefooter();
	die();
}

// update the last updated timestamp for a post/thread
function update_post_time($idx) {
	query("UPDATE board SET lasttime = ? WHERE idx = ? LIMIT 1", [time(), $idx]);
}

// MYSQL
$options = [
	PDO::ATTR_ERRMODE				=> PDO::ERRMODE_EXCEPTION,
	PDO::ATTR_DEFAULT_FETCH_MODE	=> PDO::FETCH_ASSOC,
	PDO::ATTR_EMULATE_PREPARES		=> false,
];
try {
	$sql = new PDO("mysql:host=$host;dbname=$db;charset=utf8mb4", $user, $pass, $options);
} catch (\PDOException $e) {
	die('Database error 1F');
}

function query($query,$params = []) {
	global $sql;

	$res = $sql->prepare($query);
	$res->execute($params);
	return $res;
}

function fetch($query,$params = []) {
	$res = query($query,$params);
	return $res->fetch();
}

function result($query,$params = []) {
	$res = query($query,$params);
	return $res->fetchColumn();
}

// ***************************** Top of code ********************************

if (isset($_GET['login'])) { // **** Display login form
	pageheader();
	?>
<div class="content"><form action="?login2" method="POST"><table>
	<tr><td>Username</td><td><input type="text" name="uname" maxlength="31"></td></tr>
	<tr><td>Password</td><td><input type="password" name="pass" maxlength="31"></td></tr>
	<tr><td align="center" colspan="2"><input type="submit" value="Submit"></td></tr>
</table></form></div>
	<?php
} else if (isset($_GET['login2'])) { // **** Process login
	if (result("SELECT COUNT(*) FROM users WHERE uname = ?", [$_POST['uname']]) != 1) error("User doesn't exist.");

	$userdata = fetch("SELECT idx, pass_hash, lastlogin llstamp FROM users WHERE uname=?", [$_POST['uname']]);

	if (!password_verify($_POST['pass'], $userdata['pass_hash'])) error("Authentication failed.");

	if (!isset($_COOKIE['idt-user']) || !isset($_COOKIE['idt-token'])) {
		$newid = bin2hex(random_bytes(16));
		setcookie('idt-user', $_POST['uname'], time() + 60 * 60 * 24 * 60);
		setcookie('idt-token', $newid, time() + 60 * 60 * 24 * 60);

		// store cookie in db
		query("UPDATE users SET logintoken=?, lastlogin=?, prevlogin=? WHERE idx=?", [$newid, time(), $lastlogin, $userdata['idx']]);
	} else {
		// update cookie
		setcookie('idt-user', $_COOKIE['idt-user'], time() + 60 * 60 * 24 * 60);
		setcookie('idt-token', $_COOKIE['idt-token'], time() + 60 * 60 * 24 * 60);

		// store cookie in db
		query("UPDATE users SET lastlogin = ?, prevlogin = ? WHERE idx = ?", [time(), $lastlogin, $uid]);
	}
	header("Location: ./");
} else if (isset($_GET['logout'])) { // Log Out
	setcookie('idt-user', "", time() - 3600);
	setcookie('idt-token', "", time() - 3600);

	if (isset($_COOKIE['idt-user'])) {
		query("UPDATE users SET logintoken = NULL, lastlogin = ? WHERE uname = ? AND logintoken = ?", [time(), $_COOKIE['idt-user'], $_COOKIE['idt-token']]);
	}

	header("Location: ./");
} else if (isset($_GET['adduser'])) { // **** Display form to add a user
	pageheader();
	?>
<div class="content"><form action="?adduser2" method="POST"><table>
	<tr><td>Username</td><td><input type="text" name="uname" maxlength="31"></td></tr>
	<tr><td>Password</td><td><input type="password" name="pass" maxlength="31"></td></tr>
	<tr><td>Verify Password</td><td><input type="password" name="vpass" maxlength="31"></td></tr>
	<tr><td align="center" colspan="2"><input type="submit" value="Submit"></td></tr>
</table></form></div><?php
} else if (isset($_GET['adduser2'])) { // **** Add a user to the database
	if (htmlspecialchars($_POST['uname'], ENT_QUOTES) != $_POST['uname']) error("Avoid special characters (&lt;, &gt;, &#039, &quot;) in user name ");

	// check if user already exists
	if (result("SELECT COUNT(*) FROM users WHERE uname = ?", [$_POST['uname']]) == 0) {
		if ($_POST['pass'] == $_POST['vpass']) {
			if ($_POST['pass'] == '' || $_POST['pass'][strlen($_POST['pass']) - 1] == '!') error("Please fill in all the fields.");

			$pass_hash = password_hash($_POST['pass'], PASSWORD_BCRYPT, ['cost' => 10]);
			query("INSERT INTO users SET idx=NULL, joined=?, uname=?, pass_hash=?", [time(), $_POST['uname'], $pass_hash]);

			header("Location: ./");
		} else {
			error("The passwords don't match.");
		}
	} else {
		error("An user with the name already exists.");
	}
} else if (isset($_GET['userinfo'])) { // **** User info page
	if (result("SELECT COUNT(*) FROM users WHERE idx = ?", [$_GET['userinfo']]) != 1) error("This user doesn't exist!");

	// get info from users database
	$userdata = fetch("SELECT uname, joined joindate, logintoken, postcount, lastlogin login FROM users WHERE idx = ?", [$_GET['userinfo']]);

	pageheader($userdata['uname'] . " user info");

	echo "<div class=\"content\"><strong>Info for user {$userdata['uname']}:</strong><br><br>";
	echo "Joined: " . date($datefmt, $userdata['joindate']) . "<br>";
	echo "Posts: " . $userdata['postcount'] . "<br>";

	//if ($userdata2['postcount'] > 0) {
	//	echo "Last post " . date($datefmt, $userdata2['lasttime']) . "<br>";
	//}

	if (isset($userdata['logintoken']) && $userdata['logintoken'] != "") {
		echo "Logged in " . date($datefmt, $userdata['login']) . "<br>";
	} else if ($userdata['login'] > 0) {
		echo "Last logged in " . date($datefmt, $userdata['login']) . "<br>";
	} else {
		echo "Never logged in.<br>";
	}

	echo "</div>";
} else if (isset($_GET['memberlist'])) { // **** User list
	pageheader("Memberlist");

	$query = query("SELECT uname, joined, postcount, idx uid FROM users ORDER BY postcount DESC");

	echo "<table class=\"userlist\"><tr><th colspan=4>Memberlist</th></tr><tr class=\"center\"><td>Name</td><td width=70>Posts</td><td width=120>Joined</td></tr>";
	while ($record = $query->fetch()) {
		echo "<tr class=\"center\"><td class=\"name left\"><a href=\"?userinfo={$record['uid']}\">{$record['uname']}</a></td><td>{$record['postcount']}</td><td>" . date($datefmt, $record['joined']) . "</td></tr>";
	}
	echo "</table>";
} else if (isset($_GET['chpass'])) { // **** Change password form
	if (!isset($_COOKIE['idt-user']) && !isset($_COOKIE['idt-token'])) error('You need to login!');
	pageheader();
	?>
<div class="content">
	<b>Change Password</b><br>
	<form action="?chpass2" method="POST"><table>
	<tr><td>Old Password<td><input type="password" name="oldpass" maxlength="31"></tr>
	<tr><td>New Password<td><input type="password" name="newpass" maxlength="31"></tr>
	<tr><td>Verify New Password<td><input type="password" name="vnewpass" maxlength="31"></tr>
	<tr><td align="center" colspan="2"><input type="submit" value="Submit"></tr>
	</table></form>
</div>
	<?php
} else if (isset($_GET['chpass2'])) { // **** Set new password
	if ($_POST['newpass'] != $_POST['vnewpass']) error("The passwords aren't the same!");
	if ($_POST['newpass'] == '') error("You can't have a blank password!");

	$newpass_hash = password_hash($_POST['newpass'], PASSWORD_BCRYPT, ['cost' => 10]);
	$uid = authenticate(false, $_COOKIE['idt-user'], $_POST['oldpass']);
	query("UPDATE users SET pass_hash = ? WHERE idx = ? LIMIT 1", [$newpass_hash, $uid]);

	header("Location: ./");
} else if (isset($_GET['newthread'])) {
	pageheader();
	NewPostForm(0);
} else if (isset($_GET['showthread'])) { // **** Show a single thread
	// put thread subject in title
	$subject = result("SELECT subject FROM board WHERE idx = ?", [$_GET['showthread']]);
	if ($subject == null) error("No such post found.");
	pageheader($subject);

	// count posts in thread
	$postcount = result("SELECT COUNT(*) FROM board WHERE board.replyto = ? OR board.idx = ?", [$_GET['showthread'], $_GET['showthread']]);

	$pageno = (isset($_GET['showpage']) ? $_GET['showpage'] : null);
	$lastpage = floor(($postcount - 1) / $ppp);
	if (isset($_GET['lastpage'])) {
		$pageno = $lastpage;
	}

	$firstonpage = $pageno * $ppp;

	// get user's last login time
	if (isset($_COOKIE['idt-user']) && isset($_COOKIE['idt-token'])) {
		$lastlogin = result("SELECT prevlogin llstamp FROM users WHERE uname = ?", [$_COOKIE['idt-user']]);

		if ($lastlogin == null) $lastlogin = 0;
	} else {
		$lastlogin = 0;
	}

	$query = query("
SELECT board.subject subject, board.message message, board.idx message_id, board.postedtime postedtime, board.lasttime updatetime, users.uname uname, users.idx uid
FROM board, users WHERE board.author = users.idx AND (board.replyto = ? OR board.idx = ?) ORDER BY postedtime ASC LIMIT ?,?",
	[$_GET['showthread'], $_GET['showthread'], $firstonpage, $ppp]);

	echo "<div class=\"postlist\">";
	while ($record = $query->fetch()) {
		echo "<div class=\"content\" id=\"post_{$record['message_id']}\"><span class=\"subject\">";
		if ($lastlogin > 0 && $record['updatetime'] > $lastlogin) echo "* ";
		echo "{$record['subject']}</span> by <span class=\"name\"><a href=\"?userinfo={$record['uid']}\">{$record['uname']}</a></span> at " . date($datefmt, $record['postedtime']);
		if ((isset($_COOKIE['idt-user']) && isset($_COOKIE['idt-token'])) && strcmp($record['uname'], $_COOKIE['idt-user'])) {
			echo " <a href=\"?editpost={$record['message_id']}\">[edit]</a>";
		}
		echo "</div><div class=\"content\" style=\"border-top:0px\">".$record['message'];
		echo "</div><br>";
	}
	echo "</div>Go to Page ";
	for ($i = 0; $i <= $lastpage; $i++) {
		if ($pageno != $i) echo "<a href=\"?showthread=" . $_GET['showthread'] . "&showpage=$i\">";
		echo "$i";
		if ($pageno != $i) echo "</a>";
		echo " ";
	}
	echo "<br><br>";

	NewPostForm($_GET['showthread']);
} else if (isset($_GET['addpost'])) { // **** Add a post
	$uid = authenticate(true);

	if ($_POST['inresponseto'] == "0" && (!isset($_POST['subject']) || $_POST['subject'] == "" || ctype_space($_POST['subject']))) error("Cannot start thread with empty subject.");
	if ((!isset($_POST['message']) || $_POST['message'] == "" || ctype_space($_POST['message']))) error("Please type a message for your post.");

	query("INSERT INTO board VALUES(NULL,?,?,?,?,?,?,?)",
		[time(), time(), $uid, $_POST['inresponseto'], htmlspecialchars($_POST['subject'], ENT_QUOTES), preg_replace($tags['s'], $tags['r'], htmlspecialchars($_POST['message'], ENT_QUOTES)), $_SERVER['REMOTE_ADDR']]);

	query("UPDATE users SET postcount = postcount + 1 WHERE idx = 1");

	// update thread last updated time
	if ($_POST['inresponseto'] != 0) {
		update_post_time($_POST['inresponseto']);
		header("Location: ?showthread={$_POST['inresponseto']}&lastpage");
	}
	header("Location: ?showthreads");
} else if (isset($_GET['editpost'])) { // **** Display post edit form
	$post = fetch("SELECT subject,message FROM board WHERE idx = ?", [$_GET['editpost']]);
	if ($post == null) error("Post doesn't exist.");

	pageheader();
	EditPostForm($_GET['editpost'], preg_replace($tags_decode['s'], $tags_decode['r'], $post['message']), $post['subject']);
} else if (isset($_GET['editpost2'])) { // **** Commit an edited post
	$posttoedit = intval($_POST['posttoupdate']);

	// look up what post this reponds to and when it was first posted
	$thread = fetch("SELECT replyto, postedtime FROM board WHERE idx = ? LIMIT 1", [$_POST['posttoupdate']]);
	if ($thread == null) error("Couldn't find thread.");

	$uid = authenticate(true);

	if ($query['replyto'] == "0" && (!isset($_POST['subject']) || $_POST['subject'] == "" || ctype_space($_POST['subject']))) error("Cannot start thread with empty subject.");
	if ((!isset($_POST['message']) || $_POST['message'] == "" || ctype_space($_POST['message']))) error("Please type a message for your post.");

	$message = preg_replace($tags['s'],$tags['r'],htmlspecialchars($_POST['message'],ENT_QUOTES))."<br><br><small><i>edited ".date($datefmt)."</i></small>";
	query("UPDATE board SET subject = ?, message = ?, ip = ?, lasttime = ? WHERE idx = ? AND author = ? LIMIT 1",
		[htmlspecialchars($_POST['subject'], ENT_QUOTES), $message, $_SERVER['REMOTE_ADDR'], time(), $_POST['posttoupdate'], $uid]);

	update_post_time($thread['replyto']);
	header("Location: ?showthread={$thread['replyto']}");
} else { // **** Display Threads
	pageheader();

	// get user's last login time
	if (isset($_COOKIE['idt-user']) && isset($_COOKIE['idt-token'])) {
		// login time
		$query = fetch("SELECT prevlogin llstamp FROM users WHERE uname = ?", [$_COOKIE['idt-user']]);

		if (isset($query['llstamp'])) {
			$lastlogin = $query['llstamp'];
		} else {
			$lastlogin = 0;
		}
	} else {
		$lastlogin = 0;
	}

	// first page has count($pinned_threads) + $tpp,
	// subsequent pages have $tpp
	$pagenumber = (isset($_GET['showpage']) ? $_GET['showpage'] : null);

	if ($pagenumber == 0) {
		$firstonpage = 0;
		$threadsonthispage = count($pinned_threads) + $tpp;
	} else {
		$firstonpage = count($pinned_threads) + $tpp * $pagenumber;
		$threadsonthispage = $tpp;
	}

	// thread list
	$pinned_threads_sql = "idx IN ('".join($pinned_threads, "','")."') pinned,";

	$query_str =
"SELECT
	pinned, b1.idx threadid, subject, lasttime,
	(SELECT 1+COUNT(*) FROM board WHERE replyto = threadid) postcount,
	IFNULL(lastreply, b1.idx) lastpost,
	(SELECT author FROM board WHERE idx = lastpost) lastuid,
	(SELECT uname FROM users WHERE idx = lastuid) lastuname
FROM (SELECT
	$pinned_threads_sql
	idx,
	(SELECT idx FROM board WHERE replyto = b0.idx ORDER BY postedtime DESC LIMIT 1) lastreply
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
			echo "<tr><td colspan=4>&nbsp;</td></tr>";
		}
		echo "<tr class=\"center\"><td class=\"left\"><span class=\"subject\">";
		if ($lastlogin > 0 && isset($thread['thread_lasttime']) && $thread['thread_lasttime'] > $lastlogin) {
			echo "* ";
		}

		echo "<a href=\"?showthread={$thread['threadid']}\">{$thread['subject']}</a>";
		if ($thread['pinned']) {
			$saw_pinned = 1;
			echo " <small>(pinned)</small>";
		}
		$lastpage = 0;
		if ($thread['postcount'] > $ppp) {
			$lastpage = floor(($thread['postcount'] - 1) / $ppp);
			echo " <small><a href=\"?showthread={$thread['threadid']}&lastpage\">(last page)</a></small>";
		}
		echo "</span></td>
<td>{$thread['postcount']}</td>
<td><a href=\"?showthread={$thread['threadid']}&showpage=$lastpage#post_{$thread['lastpost']}\">" . date($datefmt, $thread['lasttime']) . "</a><br>
by <span class=\"name\"><a href=\"?userinfo={$thread['lastuid']}\">{$thread['lastuname']}</a></span></td>
</tr>";
	}

	echo "</table>";

	$count = result("SELECT COUNT(*) FROM board WHERE replyto = '0'");

	$showprev = ($pagenumber > 0);
	$shownext = ($firstonpage + $threadsonthispage < $count);

	if ($showprev || $shownext) {
		echo "<br>";
		if ($showprev) echo "<a href=\"?showthreads&showpage=".($pagenumber - 1)."\">Previous Page</a>";
		if ($showprev && $shownext) echo " | ";
		if ($shownext) echo "<a href=\"?showthreads&showpage=".($pagenumber + 1)."\">Next Page</a>";
		echo "<br>";
	}
}

pagefooter();

?>