<?php
session_start();
include_once 'dbconfig.php';
require_once('class.user.php');
$user = new USER();

if($user->is_loggedin()!="")
{
  $user->redirect('index.php');
}

if(isset($_POST['btn-save']))
{
    $uname = strip_tags($_POST['txt_uname']);
    $umail = strip_tags($_POST['txt_umail']);
    $upass = strip_tags($_POST['txt_upass']);
    $ufullname = strip_tags($_POST['txt_ufullname']);
    $code = bin2hex(openssl_random_pseudo_bytes(16));

    if(strlen(trim($uname)) == 0)  {
        $error[] = "provide username !";    
    }
    else if($umail=="") {
        $error[] = "provide email id !";    
    }
    else if(!filter_var($umail, FILTER_VALIDATE_EMAIL)) {
        $error[] = 'Please enter a valid email address !';
    }
    else if($upass=="") {
        $error[] = "provide password !";
    }
    else if(strlen($upass) < 8){
        $error[] = "Password must be atleast 8 characters"; 
    }
    else if(strlen(trim($ufullname)) == 0) {
        $error[] = "provide fullname !";    
    }
    else
    {
        try
        {
            $stmt = $user->runQuery("SELECT userName, userEmail FROM users WHERE userName=:uname OR userEmail=:umail");
            $stmt->execute(array(':uname'=>$uname, ':umail'=>$umail));
            $row=$stmt->fetch(PDO::FETCH_ASSOC);
                
            if($row['userName']==$uname) {
                $error[] = "sorry username already taken !";
            }
            else if($row['userEmail']==$umail) {
                $error[] = "sorry email id already taken !";
            }
            else
            {
                if($user->register($uname,$umail,$upass,$ufullname,$code))
                 {
                    $autoid = $user->lastID();    
                    $key = base64_encode($autoid);
                    $autoid = $key;
                    
                    $message = "          
                          Hello $uname,
                          <br /><br />
                          Welcome to HMSI<br/>
                          To complete your registration  please , just click the following link<br/>
                          <br /><br />
                          <a href='localhost/peterpan/verify.php?id=$autoid&code=$code'>Click HERE to Activate</a>
                          <br /><br />
                          Thanks,";
                          
                    $subject = "Confirm Registration";
                          
                    $user->send_mail($umail,$message,$subject); 

                    header("Location: register.php?inserted");
                 }
                 else
                 {
                    header("Location: register.php?failure");
                 }
            }
        }
        catch(PDOException $e)
        {
            echo $e->getMessage();
        }
    }   
}
?>

<div class="clearfix"></div>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Peterpan : Register</title>
<link href="bootstrap/css/bootstrap.min.css" rel="stylesheet" media="screen">
<link href="bootstrap/css/bootstrap-theme.min.css" rel="stylesheet" media="screen">
<link rel="stylesheet" href="css/style.css" type="text/css"  />
</head>
<body>

<div class="signin-form">

  <div class="container">
       
          
    <form class="form-signin" method="post" id="login-form">
        
      <h2 class="form-signin-heading">Register Peterpan</h2><hr />
          <?php
            if(isset($error))
            {
                foreach($error as $error)
                {
                     ?>
                     <div class="alert alert-danger">
                        <i class="glyphicon glyphicon-warning-sign"></i> &nbsp; <?php echo $error; ?>
                     </div>
                     <?php
                }
            }
            else if(isset($_GET['inserted']))
            {
                 ?>
                 <div class="alert alert-info">
                      <i class="glyphicon glyphicon-log-in"></i> &nbsp; Successfully registered <a href='login.php'>login</a> here
                 </div>
                 <?php
            }
            ?>
          
          <div class="form-group">
            <h5>Username</h5>
            <input type='text' name='txt_uname' class='form-control' value="<?php if(isset($error)){echo $uname;}?>" maxlength="30" required>
          </div>
          
          <div class="form-group">
            <h5>Email</h5>
            <input type='text' name='txt_umail' class='form-control' value="<?php if(isset($error)){echo $umail;}?>" maxlength="60" required>
          </div>

          <div class="form-group">
          <h5>Password</h5>
            <input type='password' name='txt_upass' class='form-control' required>
          </div>

          <div class="form-group">
            <h5>Nama Lengkap</h5>
            <input type='text' name='txt_ufullname' class='form-control' maxlength="50" value="<?php if(isset($error)){echo $ufullname;}?>" required>
          </div>

          <div class="form-group">

          </div>

          <div class="form-group">

          </div>
         
        <hr />
          
          <div class="form-group">
              <button type="submit" class="btn btn-primary" name="btn-save">
                Register
             </button>  
          </div>
          <a href="fpass.php">Forgot your Password ? </a>  
          <br />
          <br/>

              <label><a href="index.php">Back to Home</a></label>
    </form>

  </div>
    
</div>

</body>
</html>