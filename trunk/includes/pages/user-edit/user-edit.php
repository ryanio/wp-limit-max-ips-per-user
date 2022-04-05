<table class="form-table">
    <tbody>
        <tr class="limit-max-ips-per-user">
            <th>
                Limit Max IPs Per User<br/>
                <small>
                    <em>
                        <a href="<?php echo(admin_url("options-general.php?page={$this->menu_slug}")) ?>" style="font-weight:normal;">Plugin Settings</a>
                    </em>
                </small>
            </th>
            <td>
                <p>
                    <strong>User status:</strong>
                    <?php echo($blocked_status_string); ?><br/>

                    <strong>
                        Number of unique IPs recorded in past
                        <?php echo($number_of_days); ?>
                        <?php echo($number_of_days == 1 ? 'day' : 'days'); ?>:
                    </strong>
                    <?php echo($number_of_unique_ips); ?><br/>

                    <?php if (isset($last_ip_address) && isset($last_ip_address_date)) { ?>
                        <strong>Last unique IP recorded:</strong>
                        <?php echo($last_ip_address); ?> (<?php echo($last_ip_address_date); ?> UTC)
                    <?php } ?>
                </p>

                <p>
                    <div id="limit-max-ips-per-user-ajax-response"></div>
                    <button type="button" id="delete-ip-records" class="button">Clear User's Recorded IPs</button>
                </p>

                <p class="description">
                    <em>Note: Restores user's login access if blocked</em>
                </p>
            </td>
        </tr>
    </tbody>
</table>