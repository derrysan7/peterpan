<?php
require_once 'class.user.php';
$user = new USER();

if(empty($_GET['id']) && empty($_GET['code']))
{
    $user->redirect('login.php');
}

if(isset($_GET['id']) && isset($_GET['code']))
{
    $id = base64_decode($_GET['id']);
    $code = $_GET['code'];
    
    $stmt = $user->runQuery("SELECT * FROM users WHERE userId=:uid AND tokenCode=:token");
    $stmt->execute(array(":uid"=>$id,":token"=>$code));
    $rows = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if($stmt->rowCount() == 1)
    {
        if(isset($_POST['btn-reset-pass']))
        {
            $pass = $_POST['pass'];
            $upass = $_POST['confirm-pass'];
            
            if(strlen($pass) < 8 or strlen($upass) < 8)
            {
                 $msg = "<div class='alert alert-block'>
                                <button class='close' data-dismiss='alert'>&times;</button>
                                <strong>Sorry!</strong>  Password must be atleast 8 characters. 
                                </div>";   
            }else{

                if($upass!==$pass)
                    {
                        $msg = "<div class='alert alert-block'>
                                <button class='close' data-dismiss='alert'>&times;</button>
                                <strong>Sorry!</strong>  Password Doesn't match. 
                                </div>";
                    }
                    else
                    {
                        $password = password_hash($upass, PASSWORD_DEFAULT);
                        $stmt = $user->runQuery("UPDATE users SET userPass=:upass WHERE userId=:uid");
                        $stmt->execute(array(":upass"=>$password,":uid"=>$rows['userId']));

                        $code2 = bin2hex(openssl_random_pseudo_bytes(16));
                        $stmt = $user->runQuery("UPDATE users SET tokenCode=:token2 WHERE tokenCode=:token");
                        $stmt->execute(array(":token2"=>$code2,"token"=>$code));
                        
                        $msg = "<div class='alert alert-success'>
                                <button class='close' data-dismiss='alert'>&times;</button>
                                Password Changed.
                                </div>";
                        header("refresh:5;login.php");
                    }
                    
            }
        }   
    }
    else
    {
        $msg = "<div class='alert alert-success'>
                <button class='close' data-dismiss='alert'>&times;</button>
                No Account Found, Try again
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
<body id="login">
    <div class="container">
        <div class='alert alert-success'>
            <strong>Hello !</strong>  <?php echo $rows['userName'] ?> you are here to reset your forgetton password.
        </div>
        <form class="form-signin" method="post">
        <h3 class="form-signin-heading">Password Reset.</h3><hr />
        <?php
        if(isset($msg))
        {
            echo $msg;
        }
        ?>
        <input type="password" class="input-block-level" placeholder="New Password" name="pass" required /> <br/> <br/>
        <input type="password" class="input-block-level" placeholder="Confirm New Password" name="confirm-pass" required />
        <hr />
        <button class="btn btn-large btn-primary" type="submit" name="btn-reset-pass">Reset Your Password</button>
        
      </form>

    </div> <!-- /container -->
    <script src="bootstrap/js/jquery-1.11.3-jquery.min.js"></script>
    <script src="bootstrap/js/bootstrap.min.js"></script>
  </body>
</html>