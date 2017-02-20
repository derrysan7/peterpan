<?php

class crud
{
 private $db;
 
 function __construct($DB_con)
 {
  $this->db = $DB_con;
 }

 public function runQuery($sql)
  {
    $stmt = $this->db->prepare($sql);
    return $stmt;
  }

 public function lasdID()
  {
    $stmt = $this->db->lastInsertId();
    return $stmt;
  }
 
 public function create($uname,$umail,$upass,$ufullname,$uperm,$utokencode)
 {
  try
  {
    $new_password = password_hash($upass, PASSWORD_DEFAULT);
      if($uperm == "Super Admin") {
         $new_perm = "1";
         }
         else{
         $new_perm = "2";
       }

   $stmt = $this->db->prepare("INSERT INTO users(userName,userEmail,userPass,fullname,kodePermission,tokenCode) 
                                                   VALUES(:uname, :umail, :upass, :ufullname,:uperm, :active_code)");
   $stmt->bindparam(":uname", $uname);
   $stmt->bindparam(":umail", $umail);
   $stmt->bindparam(":upass", $new_password);
   $stmt->bindparam(":ufullname", $ufullname);
   $stmt->bindparam(":uperm", $new_perm);
   $stmt->bindparam(":active_code",$utokencode);
   $stmt->execute();
   return true;
  }
  catch(PDOException $e)
  {
   echo $e->getMessage(); 
   return false;
  }
  
 }

 
 public function getID($userId)
 {
  $stmt = $this->db->prepare("SELECT * FROM users WHERE userId=:userId");
  $stmt->execute(array(":userId"=>$userId));
  $editRow=$stmt->fetch(PDO::FETCH_ASSOC);
  return $editRow;
 }
 
 public function update($userId,$uname,$umail,$ufullname,$uperm)
 {
  try
  {
      if($uperm == "Super Admin") {
         $new_perm = "1";
         }
         else{
         $new_perm = "2";
       }
   $stmt=$this->db->prepare("UPDATE users SET userName=:uname, 
                                              userEmail=:umail, 
                                              fullname=:ufullname, 
                                              kodePermission=:uperm
                                            
             WHERE userId=:userId ");
   $stmt->bindparam(":uname", $uname);
   $stmt->bindparam(":umail", $umail);
   $stmt->bindparam(":ufullname", $ufullname);
   $stmt->bindparam(":uperm", $new_perm);
   $stmt->bindparam(":userId",$userId);
   $stmt->execute();
   
   return true; 
  }
  catch(PDOException $e)
  {
   echo $e->getMessage(); 
   return false;
  }
 }

  public function update_pass($userId,$upass)
 {
  try
  {
    $new_password = password_hash($upass, PASSWORD_DEFAULT);

   $stmt=$this->db->prepare("UPDATE users SET userPass=:upass WHERE userId=:userId");
   $stmt->bindparam(":upass", $new_password);
   $stmt->bindparam(":userId",$userId);
   $stmt->execute();
   
   return true; 
  }
  catch(PDOException $e)
  {
   echo $e->getMessage(); 
   return false;
  }
 }

 function send_mail($email,$message,$subject)
  {           
    require_once('mailer/class.phpmailer.php');
    $mail = new PHPMailer();
    $mail->IsSMTP(); 
    $mail->SMTPDebug  = 0;
    $mail->SMTPAuth   = true;
    $mail->SMTPSecure = "ssl";
    $mail->Host       = "smtp.gmail.com";
    $mail->Port       = 465; 
    $mail->AddAddress($email);
    $mail->Username="hmsi@si.ukdw.ac.id";
    $mail->Password="2016Uyee";
    $mail->SetFrom('hmsi@si.ukdw.ac.id','Admin HSMI UKDW');
    $mail->AddReplyTo("hmsi@si.ukdw.ac.id","Admin HSMI UKDW");
    $mail->Subject = $subject;
    $mail->MsgHTML($message);
    $mail->Send();
  }
 
 public function delete($userId)
 {
  $stmt = $this->db->prepare("DELETE FROM users WHERE userId=:userId");
  $stmt->bindparam(":userId",$userId);
  $stmt->execute();
  return true;
 }
 
 /* paging */
 
 public function dataview($query)
 {
  $stmt = $this->db->prepare($query);
  $stmt->execute();
 
  if($stmt->rowCount()>0)
  {
   while($row=$stmt->fetch(PDO::FETCH_ASSOC))
   {
    if($row['kodePermission']==1){
      $namaPermission = "Super Admin";
    } else{
      $namaPermission = "Author";
    }
    
    ?>
                <tr>
                <td><?php print($row['userId']); ?></td>
                <td><?php print($row['userName']); ?></td>
                <td><?php print($row['userEmail']); ?></td>
                <td><?php print($row['fullname']); ?></td>
                <td><?php print($namaPermission); ?></td>
                <td align="center">
                <a href="edit-data.php?edit_id=<?php print($row['userId']); ?>"><i class="glyphicon glyphicon-edit"></i></a>
                </td>
                <td align="center">
                <a href="delete.php?delete_id=<?php print($row['userId']); ?>"><i class="glyphicon glyphicon-remove-circle"></i></a>
                </td>
                </tr>
                <?php
   }
  }
  else
  {
   ?>
            <tr>
            <td>Nothing here...</td>
            </tr>
            <?php
  }
  
 }
 
 public function paging($query,$records_per_page)
 {
  $starting_position=0;
  if(isset($_GET["page_no"]))
  {
   $starting_position=($_GET["page_no"]-1)*$records_per_page;
  }
  $query2=$query." limit $starting_position,$records_per_page";
  return $query2;
 }
 
 public function paginglink($query,$records_per_page)
 {
  
  $self = $_SERVER['PHP_SELF'];
  
  $stmt = $this->db->prepare($query);
  $stmt->execute();
  
  $total_no_of_records = $stmt->rowCount();
  
  if($total_no_of_records > 0)
  {
   ?><ul class="pagination"><?php
   $total_no_of_pages=ceil($total_no_of_records/$records_per_page);
   $current_page=1;
   if(isset($_GET["page_no"]))
   {
    $current_page=$_GET["page_no"];
   }
   if($current_page!=1)
   {
    $previous =$current_page-1;
    echo "<li><a href='".$self."?page_no=1'>First</a></li>";
    echo "<li><a href='".$self."?page_no=".$previous."'>Previous</a></li>";
   }
   for($i=1;$i<=$total_no_of_pages;$i++)
   {
    if($i==$current_page)
    {
     echo "<li><a href='".$self."?page_no=".$i."' style='color:red;'>".$i."</a></li>";
    }
    else
    {
     echo "<li><a href='".$self."?page_no=".$i."'>".$i."</a></li>";
    }
   }
   if($current_page!=$total_no_of_pages)
   {
    $next=$current_page+1;
    echo "<li><a href='".$self."?page_no=".$next."'>Next</a></li>";
    echo "<li><a href='".$self."?page_no=".$total_no_of_pages."'>Last</a></li>";
   }
   ?></ul><?php
  }
 }
 
 /* paging */
 
}