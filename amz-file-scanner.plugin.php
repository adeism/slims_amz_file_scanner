<?php
/**
 * Plugin Name: AMZ File Scanner
 * Plugin URI: https://github.com/adeism/slims_amz_file_scanner
 * Description: Memindai folder SLiMS dari file ilegal dan pola malware yang umum digunakan untuk menyusup ke dalam sistem. Terinspirasi dari postingan Pak Hendro Wicaksono di Whatsapp Group SLiMS github.com/hendrowicaksono/slims-clean-image/blob/master/clean-image.php
 * Version: 1.0.0
 * Author: Ade Ismail Siregar 
 */

defined('INDEX_AUTH') OR die('Direct access not allowed');

require_once __DIR__ . '/helper.php';

$plugin = \SLiMS\Plugins::getInstance();
$plugin->registerMenu('system', 'AMZ File Scanner', __DIR__ . '/admin_menu.php');
