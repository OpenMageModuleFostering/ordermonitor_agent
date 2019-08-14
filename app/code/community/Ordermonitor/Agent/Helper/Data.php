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
class Ordermonitor_Agent_Helper_Data extends Mage_Core_Helper_Abstract
{
    const XML_PATH_OM_VERSION    = 'ordermonitor/general_configuration/om_version';
    const XML_PATH_OM_USERNAME   = 'ordermonitor/general_configuration/om_username';
    const XML_PATH_OM_KEY        = 'ordermonitor/general_configuration/om_key';
    const XML_PATH_OM_DEBUG_FLAG = 'ordermonitor/general_configuration/om_debug';

    public function getOmKey($store = null)
    {
        return Mage::getStoreConfig(self::XML_PATH_OM_KEY, $store);
    }

    public function getOmUsername($store = null)
    {
        return Mage::getStoreConfig(self::XML_PATH_OM_USERNAME, $store);
    }

    public function getOmDebugFlag($store = null)
    {
        return (bool)Mage::getStoreConfigFlag(self::XML_PATH_OM_DEBUG_FLAG, $store);
    }

    public function getOmVersion($store = null)
    {
        return Mage::getStoreConfig(self::XML_PATH_OM_VERSION, $store);
    }
}