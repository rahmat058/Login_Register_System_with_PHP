 <?php 
  include 'lib/User.php';
  include 'inc/header.php';
  Session::checkSession();
  $user = new User();
?>

<?php
  $loginmsg = Session::get("loginmsg");
      if ($loginmsg) {
  	  echo $loginmsg;
  	  Session::set('loginmsg',NULL);
  }
?>
       	 <div class="panel panel-default">
       	 	<div class="panel-heading">
       	 		<h2>User List: <span class="pull-right">Welcome!<strong>

       	 		<?php
                   $name = Session::get("username");
                   if (isset($name)) {
                   	echo $name;
                   }
       	 		?>
                 </strong></span></h2>
       	 	</div>

       	 	<div class="panel-body">
       	 		<table class="table table-striped">
       	 			<tr>
	       	 			<th width="20%">Serial</th>
	       	 			<th width="20%">Name</th>
	       	 			<th width="20%">UserName</th>
	       	 			<th width="20%">Email Address</th>
	       	 			<th width="20%">Action</th>
	       	 		</tr>

<?php
  
  $user = new User();
  $userdata = $user->getUserData();
  if ($userdata) {
  	$i=0;
  	foreach ($userdata as $sdata) {
  	$i++;
?>
	       	 		<tr>
	       	 			<td><?php echo $i; ?></td>
	       	 			<td><?php echo $sdata['name']; ?></td>
	       	 			<td><?php echo $sdata['username']; ?></td>
	       	 			<td><?php echo $sdata['email']; ?></td>
	       	 			<td>
	       	 			   <a class="btn btn-primary" href="profile.php?id=<?php echo $sdata['id']; ?>">View</a>
	       	 			</td>
	       	 		</tr>
<?php } } else{ ?>
                     <tr>
                     	<td colspan="5">
                     	   <h2>No User Data Found.....</h2>
                     	</td>
                     </tr>
<?php } ?>	
       	 		</table>
       	 	</div>
       	 </div>

<?php
   include 'inc/footer.php';
?>