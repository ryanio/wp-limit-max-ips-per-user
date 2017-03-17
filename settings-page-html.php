<style>
 h2 {
  margin-top: 40px;
}

h2:first-of-type {
  margin-top: 0;
}

p.submit {
  margin-top: 10px;
  margin-bottom: 30px;
}

.destroy-ip-records .button {
  margin-bottom: 10px;
}
</style>

<div class="wrap">
  <h1>Limit Max IPs Per User</h1>

  <form method="post" action="options.php">
    <?php
    settings_fields('limit_max_ips_per_user_settings');
    do_settings_sections('limit_max_ips_per_user_settings');
    submit_button('Save Settings');
    ?>
  </form>

  <h2>Login Log</h2>

  <table id="log" class="display" cellspacing="0" width="100%">
    <thead>
      <tr>
        <th>#</th>
        <th>User ID</th>
        <th>Username</th>
        <th>Email</th>
        <th>IP Address</th>
        <th>Time</th>
        <th>Login blocked?</th>
      </tr>
    </thead>
    <tbody>

      <?php foreach ($log as $row) { ?>

      <tr>
        <td><?php echo($row['id']); ?></td>
        <td><?php echo($row['user_id']); ?></td>
        <td><?php echo($row['user_login']); ?></td>
        <td><?php echo($row['user_email']); ?></td>
        <td><?php echo($row['ip']); ?></td>
        <td><?php echo($row['time']); ?> UTC</td>
        <td><?php echo($row['login_blocked'] ? '<span style="color: red;font-weight: bold;">Yes</span>' : 'No'); ?></td>
      </tr>

      <?php } ?>

    </tbody>
  </table>

  <h2>Clear Login Records</h2>

  <p class="destroy-ip-records">
    <a href="?destroy_ip_records=true" class="button" onclick="javascript:return confirm('Are you sure? Please note this action cannot be reversed.');">Clear Login Records</a><br/>
    <em>Note: This deletes all recorded IP history and allows everyone to log in again.</em>
  </p>

  <link rel="stylesheet" type="text/css" href="//cdn.datatables.net/1.10.13/css/jquery.dataTables.min.css">
  <script type="text/javascript" language="javascript" src="//cdn.datatables.net/1.10.13/js/jquery.dataTables.min.js"></script>

  <script>
    jQuery(document).ready(function() {
      jQuery('#log').DataTable({
        'order': [0, 'dsc']
      });
    });
  </script>

  <h2>Support</h2>
  <p>This plugin is made by Ryan Ghods, you may email him for support inquiries at <a href="mailto:ryan@ryanio.com">ryan@ryanio.com</a>.</p>

  <p>If you'd like to say thanks for this plugin, please consider making a donation via PayPal <a target="_blank" href="https://paypal.me/ryanghods">here</a> :)</p>
</div>