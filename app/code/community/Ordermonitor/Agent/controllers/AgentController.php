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
class Ordermonitor_Agent_AgentController extends Mage_Core_Controller_Front_Action
{
    const OM_AUTH_FAIL = 'Invalid authentication. Please check your account name and api key.';

    protected $_auth = false;

    protected function _initAgent()
    {
        date_default_timezone_set('UTC');

        $hash = $this->getRequest()->getParam('hash');

        $om = Mage::getModel('ordermonitor_agent/monitor');

        if (!empty($hash) && $hash === $om->getHash()) {
            $this->_auth = true;
        }
    }

    public function dataAction()
    {
        $this->_initAgent();

        $results = array();

        $request = $this->getRequest();

        // require start and end dates
        $start = strtotime($request->getParam('start', '2013-01-01 00:00:00'));
        $end   = strtotime($request->getParam('end', '2013-01-01 00:00:01'));

        $storeIds          = json_decode($request->getParam('stores', '["0"]'));
        $skus              = json_decode($request->getParam('skus', '[]'));
        $getOrderTotals    = (bool)$request->getParam('orderTotals', 1);
        $getItemTotals     = (bool)$request->getParam('itemTotals', 0);
        $getCartTotals     = (bool)$request->getParam('cartTotals', 0);
        $getMinMaxPrices   = (bool)$request->getParam('maxMinPrices', 0);
        $checkStock        = (bool)$request->getParam('checkStock', 0);
        $getCustomerTotals = (bool)$request->getParam('customerTotals', 0);
        $getCronStatus     = (bool)$request->getParam('cronJobs', 1);
        $stockAlertSkus    = json_decode($request->getParam('stockSkus', '[]'));
        $stockMinQty       = (int)$request->getParam('stockMinQty', 0);
        $limit             = (int)$request->getParam('limit', 100);
        $customerGroupId   = (int)$request->getParam('customerGroup', '');
        
        $om = Mage::getModel('ordermonitor_agent/monitor');
        
        if ($om->storeIdsOk($storeIds) === false) {
            $results['error']['code']    = '1';
            $results['error']['message'] = 'Invalid store id(s).';
        } else {
            if ($this->_auth === true) {
                $storeIds = array_map("intval", $storeIds);
                $params = array(
                    'getOrderTotals'  => $getOrderTotals, 
                    'getMinMaxPrices' => $getMinMaxPrices, 
                    'customerGroupId' => $customerGroupId
                    );
                
                $results = $om->getOrderInfo($start, $end, $storeIds, $params);
                $om->getCartInfo($start, $end, $storeIds);

                if ($getItemTotals === true) {
                    $itemTotals = $om->getItemTotals($start, $end, $storeIds, $skus, $limit);

                    $results['info']['itemTotals']             = $itemTotals['items'];
                    $results['info']['runTime']               += $itemTotals['runTime'];
                    $results['info']['runTimes']['itemTotals'] = $itemTotals['runTime'];
                }
                
                if($checkStock === true){
                    $inventory   = Mage::getModel('ordermonitor_agent/inventory');
                    $stockAlerts = $inventory->getStockAlertBySkus($stockAlertSkus, $stockMinQty);
                    
                    $results['info']['stockAlerts']             = $stockAlerts['data'];
                    $results['info']['runTime']                += $stockAlerts['runTime'];
                    $results['info']['runTimes']['stockCheck']  = $stockAlerts['runTime'];
                }

                if ($getCartTotals === true) {
                    $cartTotals = $om->getCartInfo($start, $end, $storeIds);

                    $results['info']['newCarts']                = $cartTotals['data']['newCarts'];
                    $results['info']['updatedCarts']            = $cartTotals['data']['updatedCarts'];
                    $results['info']['newCartsActive']          = $cartTotals['data']['newCartsActive'];
                    $results['info']['updatedCartsActive']      = $cartTotals['data']['updatedCartsActive'];
                    $results['info']['runTime']                += $cartTotals['runTime'];
                    $results['info']['runTimes']['cartTotals']  = $cartTotals['runTime'];
                }
                
                 if ($getCustomerTotals === true) {
                    $customerTotals = $om->getCustomerTotals($start, $end, $storeIds, 'all');

                    $results['info']['customerTotals']             = $customerTotals['items'];
                    $results['info']['runTime']                   += $customerTotals['runTime'];
                    $results['info']['runTimes']['customerTotals'] = $customerTotals['runTime'];
                }

                if ($getCronStatus === true) {
                    $cron   = Mage::getModel('ordermonitor_agent/cron');
                    $results['cron'] = $cron->getCronStatus();
                }
                
            } else {
                $results['error']['code']    = '1';
                $results['error']['message'] = self::OM_AUTH_FAIL;
            }
        }

        $json = json_encode($results);

        $this->getResponse()->setHeader('Content-type', 'application/json');
        $this->getResponse()->setBody($json);
    }


    public function setupAction()
    {
        $this->_initAgent();

        $results = array();

        if ($this->_auth === true) {
            $om = Mage::getModel('ordermonitor_agent/monitor');
            $results['info']['versions']       = $om->getVersions();
            $results['info']['websites']       = $om->getStores();
            $results['info']['customerGroups'] = $om->getCustomerGroupsList();
        } else {
            $results['error']['code']    = '1';
            $results['error']['message'] = self::OM_AUTH_FAIL;
        }
        
        $json = json_encode($results);

        $this->getResponse()->setHeader('Content-type', 'application/json');
        $this->getResponse()->setBody($json);
    }

    public function securityAction()
    {
        $om = Mage::getModel('ordermonitor_agent/secure');
        $results = $om->getSecureInfo();

        $json = json_encode($results);

        $this->getResponse()->setHeader('Content-type', 'application/json');
        $this->getResponse()->setBody($json);

    }
    
}
