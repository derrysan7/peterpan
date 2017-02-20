<?php
session_start();
require_once 'class.user.php';
$user = new USER();

if($user->is_loggedin()!="")
{
	$user->redirect('index.php');
}

if(isset($_POST['btn-submit']))
{
	$email = $_POST['txtemail'];
	
	$stmt = $user->runQuery("SELECT userId FROM users WHERE userEmail=:email LIMIT 1");
	$stmt->execute(array(":email"=>$email));
	$row = $stmt->fetch(PDO::FETCH_ASSOC);	
	if($stmt->rowCount() == 1)
	{
		$id = base64_encode($row['userId']);
		$code = bin2hex(openssl_random_pseudo_bytes(16));
		
		$stmt = $user->runQuery("UPDATE users SET tokenCode=:token WHERE userEmail=:email");
		$stmt->execute(array(":token"=>$code,"email"=>$email));
		
		$message= "
				   Hello , $email
				   <br /><br />
				   We got requested to reset your password, if you do this then just click the following link to reset your password, if not just ignore                   this email,
				   <br /><br />
				   Click Following Link To Reset Your Password 
				   <br /><br />
				   <a href='https://hmsi.fti.ukdw.ac.id/resetpass.php?id=$id&code=$code'>Click HERE to reset your password</a>
				   <br /><br />
				   Thank you
				   ";
		$subject = "Password Reset";
		
		$user->send_mail($email,$message,$subject);
		
		$msg = "<div class='alert alert-success'>
					<button class='close' data-dismiss='alert'>&times;</button>
					We've sent an email to $email.
                    Please click on the password reset link in the email to generate new password. 
			  	</div>";
	}
	else
	{
		$msg = "<div class='alert alert-success'>
					<button class='close' data-dismiss='alert'>&times;</button>
					We've sent an email to $email.
                    Please click on the password reset link in the email to generate new password. 
			  	</div>";
	}
}
?>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>HMSI : Login</title>
<link href="bootstrap/css/bootstrap.min.css" rel="stylesheet" media="screen">
<link href="bootstrap/css/bootstrap-theme.min.css" rel="stylesheet" media="screen">
<link rel="stylesheet" href="css/style.css" type="text/css"  />
</head>
<body>

<div class="signin-form">

	<div class="container">
     
        
       	<form class="form-signin" method="post">
	        <h2 class="form-signin-heading">Forgot Password</h2><hr />
	        
	        	<?php
				if(isset($msg))
				{
					echo $msg;
				}
				else
				{
					?>
	              	<div class='alert alert-info'>
					Please enter your email address. You will receive a link to create a new password via email.!
					</div>  
	                <?php
				}
				?>
	        
	        <input type="email" class="input-block-level" placeholder="Email address" name="txtemail" style="width: 261px;" required />
	     	<hr />
	        <button class="btn btn-danger btn-primary" type="submit" name="btn-submit">Generate new Password</button>
	     </form>

    </div>
    
</div>
<script src="bootstrap/js/jquery-1.11.3-jquery.min.js"></script>
<script src="bootstrap/js/bootstrap.min.js"></script>
</body>
</html>