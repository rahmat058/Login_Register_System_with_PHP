<?php
    include_once 'Session.php';
    include_once 'Database.php';

   class User{
   /************** Database Connection ***************/

     private $db;
   	 public function __construct(){
   		$this->db = new Database(); 
   	}
      
   /************** End Database Connection ***************/


  /*************************** User Registration Method *******************************************/
   	public function userRegistration($data){
           $name         = $data['name'];
           $username     = $data['username'];
           $email        = $data['email'];
           $password     = $data['password'];
           
           $chk_email = $this->emailcheck($email);

             if($name=="" OR $username=="" OR $email=="" OR $password==""){
             $msg = "<div class='alert alert-danger'><strong>Error ! </strong> Filled must not be empty</div>";

               return $msg;
           }

          if(strlen($username) < 3){
           	  $msg = "<div class='alert alert-danger'><strong>Error ! </strong> User Name is Too Short.</div>";
              return $msg;
           }elseif(preg_match('/[^a-z0-9_-]+/i', $username)){
              $msg = "<div class='alert alert-danger'><strong>Error ! </strong> UserName must only contain 
                      alphanumerical,dashes,underscores!</div>";
           }
           
           if(filter_var($email,FILTER_VALIDATE_EMAIL)===false){
             $msg = "<div class='alert alert-danger'><strong>Error ! </strong>Email address is not valid</div>";
              return $msg;
           }

           if($chk_email==true){
             $msg = "<div class='alert alert-danger'><strong>Error ! </strong>Your Email already Exists!</div>";
              return $msg;
           }
           
           $password     = md5($data['password']);

           $sql = "INSERT INTO tbl_user(name,username,email,password)   VALUES(:name,:username,:email,:password)";
           $query = $this->db->pdo->prepare($sql);
           $query->bindvalue(":name",$name);
           $query->bindvalue(":username",$username);
           $query->bindvalue(":email",$email);
           $query->bindvalue(":password",$password);
           $result = $query->execute();

           if ($result) {
           	$msg = "<div class='alert alert-success'><strong>Success!</strong>Your Registration is Successful! </div>";
              return $msg;
           }else{
           	$msg = "<div class='alert alert-danger'><strong>Error ! </strong>Your Registration is Failed!</div>";
              return $msg;
           }

       }


       public function emailcheck($email){
           $sql = "SELECT email FROM tbl_user WHERE email=:email";
           $query = $this->db->pdo->prepare($sql);
           $query->bindvalue(":email",$email);
           $query->execute();

           if($query->rowCount() > 0){
              return true;
           }else{
           	  return false;
           }
   	    }

/*************************** End User Registration Method *******************************************/


   	    public function getLoginUser($email,$password){
           $sql = "SELECT * FROM tbl_user WHERE email=:email AND password=:password LIMIT 1";
           $query = $this->db->pdo->prepare($sql);
           $query->bindvalue(":email",$email);
           $query->bindvalue(":password",$password);
           $query->execute();
           $result = $query->fetch(PDO::FETCH_OBJ);
           return $result;
        }

         public function userLogin($data){
           $email        = $data['email'];
           $password     = md5($data['password']);

           $chk_email = $this->emailcheck($email);

             if($email=="" OR $password==""){
             $msg = "<div class='alert alert-danger'><strong>Error ! </strong> Filled must not be empty</div>";

               return $msg;
           }

           if(filter_var($email,FILTER_VALIDATE_EMAIL)===false){
             $msg = "<div class='alert alert-danger'><strong>Error ! </strong>Email address is not valid</div>";
              return $msg;
           }

           if($chk_email==false){
             $msg = "<div class='alert alert-danger'><strong>Error ! </strong>Your Email Not Exists!</div>";
              return $msg;
           }

           $result = $this->getLoginUser($email,$password);
           if ($result) {
           	Session::init();
           	Session::set('login',true);
           	Session::set('id', $result->id);
           	Session::set('name', $result->name);
           	Session::set('username', $result->username);
           	Session::set('loginmsg', "<div class='alert alert-success'><strong>Success ! </strong>You are logged in!</div>");

           	header("Location: index.php");  

           }else{
           	$msg = "<div class='alert alert-danger'><strong>Error ! </strong>Data not Found!</div>";
              return $msg;
           }
   	    }

   	    public function getUserData(){
   	       $sql = "SELECT * FROM tbl_user ORDER BY id DESC";
           $query = $this->db->pdo->prepare($sql);
           $query->execute();
           $result = $query->fetchall();
           return $result;
   	    }

   	    public function getUserById($id){
   	    	 $sql = "SELECT * FROM tbl_user WHERE id=:id limit 1";
           $query = $this->db->pdo->prepare($sql);
           $query->bindValue(':id',$id);
           $query->execute();
           $result = $query->fetch(PDO::FETCH_OBJ);
           return $result;
   	    }

   	    public function updateUserData($id,$data){
           $name         = $data['name'];
           $username     = $data['username'];
           $email        = $data['email'];

             if($name=="" OR $username=="" OR $email==""){
             $msg = "<div class='alert alert-danger'><strong>Error ! </strong> Filled must not be empty</div>";

               return $msg;
           }

           $sql = "UPDATE tbl_user set 
                   name     = :name,
                   username = :username,
                   email    = :email
                   WHERE id = :id";

           $query = $this->db->pdo->prepare($sql);
           $query->bindvalue(":name",$name);
           $query->bindvalue(":username",$username);
           $query->bindvalue(":email",$email);
           $query->bindvalue(":id",$id);
           $result = $query->execute();

           if ($result) {
           	$msg = "<div class='alert alert-success'><strong>Success!</strong>User Data Updated Successful! 
           	</div>";
              return $msg;
           }else{
           	$msg = "<div class='alert alert-danger'><strong>Error ! </strong>UserData Not Updated !</div>";
              return $msg;
           }
   	    }


   	    private function checkPassword($id,$old_pass){
           $password = md5($old_pass);
           $sql = "SELECT password FROM tbl_user WHERE id=:id AND password=:password  ";
           $query = $this->db->pdo->prepare($sql);
           $query->bindvalue(":id",$id);
           $query->bindvalue(":password",$password);
           $query->execute();

           if($query->rowCount() > 0){
              return true;
           }else{
           	  return false;
           }
   	    }


   	    public function updatePassword($id,$data){
            $old_pass = $data['old_pass']; 
            $new_pass = $data['password'];
            $chk_pass = $this->checkPassword($id,$old_pass);

            if ($old_pass == "" OR $new_pass == "") {
            $msg = "<div class='alert alert-danger'><strong>Error ! </strong>Field must not be empty! </div>";
              return $msg;
            }

            
            if ($chk_pass == false) {
            $msg = "<div class='alert alert-danger'><strong>Error ! </strong>Old Password Not Exists! </div>";
              return $msg;
               }

            if (strlen($new_pass) < 6) {
             	 $msg = "<div class='alert alert-danger'><strong>Error ! </strong>Password is Too short! </div>";
              return $msg;
             }


           $password = md5($new_pass);

           $sql = "UPDATE tbl_user set 
                   password = :password
                   WHERE id = :id";

           $query = $this->db->pdo->prepare($sql);

           $query->bindvalue(":password",$password);
           $query->bindvalue(":id",$id);
           $result = $query->execute();

           if ($result) {
           	$msg = "<div class='alert alert-success'><strong>Success!</strong>Password Updated Successful! 
           	</div>";
              return $msg;
           }else{
           	$msg = "<div class='alert alert-danger'><strong>Error ! </strong>Password Not Updated !</div>";
              return $msg;
           }
            
   	    }

   	    

}

   
?> 