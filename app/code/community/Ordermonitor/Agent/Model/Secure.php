<?php
/**
 * Order Monitor
 *
 * @category    Ordermonitor
 * @package     Ordermonitor_Agent
 * @author      Digital Operative <codemaster@digitaloperative.com>
 * @copyright   Copyright (C) 2015 Digital Operative
 * @license     http://www.ordermonitor.com/license
 */
class Ordermonitor_Agent_Model_Secure extends Mage_Core_Model_Abstract
{

    /**
     * Gets information about the security settings for Magento
     *
     * @return array security check data
     */
    public function getSecureInfo()
    {
        $results = array();

        /*
        admin/security/use_form_key 1
        admin/security/session_cookie_lifetime	3600
        admin/security/lockout_failures	6
        admin/security/lockout_threshold	30
        admin/security/password_lifetime	90
        admin/security/password_is_forced	1
        */

        $results['captchaEnabled'] = Mage::getStoreConfig('admin/captcha/enable');
        $results['adminHttps'] = Mage::getStoreConfig('web/secure/use_in_adminhtml');

        //CASE SENSATIVE - password is always case, used for username
        $results['loginCaseSensitive'] = Mage::getStoreConfig('admin/security/use_case_sensitive_login');
        $results['adminPathOk'] = $this->_checkAdminUrlPath();
        $results['localXmlSecured'] = $this->_checkLocalXmlPublic();

        $results['adminUsername'] = $this->_checkAdminUsernames();

        $passwordUsers = $this->_checkAdminPasswords();

        if (count($passwordUsers) > 0) {
            $results['passwordsOk'] = 0;
        } else {
            $results['passwordsOk'] = 1;
        }

        $results['badPasswords'] = array('numUsers' => count($passwordUsers), 'usernames' => $passwordUsers);

        return $results;
    }


    private function _checkAdminUrlPath()
    {
        $badPaths = array('admin');
        $adminUrlPath = Mage::getConfig()->getNode('admin/routers/adminhtml/args/frontName');

        if(Mage::getStoreConfig('admin/url/use_custom_path') === 1) {
            $adminUrlPath = Mage::getStoreConfig('admin/url/custom_path');
        }

        if (in_array($adminUrlPath, $badPaths)) {
            return 0;
        }

        return 1;
    }


    private function _checkAdminUsernames()
    {
        $badUsernames = array('admin');

        $admin = Mage::getModel("admin/user");
        $admins = $admin->getCollection()
            ->addFieldToFilter('username', array('in' => $badUsernames));

        $adminUsers = $admins->load()->toArray();

        return $adminUsers['totalRecords'];
    }

    private function _checkAdminPasswords()
    {
        $badPasswords = array(
            '123456789',
            '12345678',
            '1234567',
            '69696969',
            '123123123',
            'password',
            'trustno1',
            'adminadmin',
            'admin123',
            'magento',
            'abc1234',
            'iloveyou',
            'football',
            'baseball',
            'superman',
            'letmein'
        );

        $badUsers = array();

        $admin = Mage::getModel("admin/user");
        $admins = $admin->getCollection()
            ->addFieldToFilter('is_active', array('eq' => 1));

        $adminUsers = $admins->load();

        foreach ($adminUsers as $user) {
            foreach ($badPasswords as $password) {
                if ($admin->authenticate($user->username, $password) == true) {
                    $badUsers[] = $user->username;
                }
            }
        }

        return $badUsers;
    }


    private function _checkLocalXmlPublic()
    {
        $url = Mage::getBaseUrl(Mage_Core_Model_Store::URL_TYPE_WEB) . 'app/etc/local.xml';

        $client = new Varien_Http_Client();
        $client->setUri($url)
            ->setMethod('GET')
            ->setConfig(
                array(
                    'maxredirects' => 1,
                    'timeout'      => 15,
            ));

        try {
            $response = $client->request();
            $statusCode = $response->getStatus();
        } catch (Exception $e) {
            $statusCode = 0;
        }

        if ($statusCode === 403) {
            return 1;
        }

        return 0;
    }

}
