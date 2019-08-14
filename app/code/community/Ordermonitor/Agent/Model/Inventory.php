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
class Ordermonitor_Agent_Model_Inventory extends Mage_Core_Model_Abstract
{
  
    /**
     * Get skus that are below the min stock quantity for a given list of skus
     * 
     * @param array $skus array of skus to check
     * @param int $minQty min quantity to throw an alert
     * @return array array of skus below min quantity and its stock value
     */
    public function getStockAlertBySkus($skus = array(), $minQty = 0)
    {
     
        $startTime = microtime(true);
        
        $results = array();
        
        $stock = Mage::getModel('catalog/product')
                ->getCollection()
                ->addAttributeToSelect(array('sku'))
                ->addAttributeToFilter('sku', $skus)
                ->addAttributeToFilter('type_id', array('in' => array('simple', 'virtual')));

        $stock->joinTable('cataloginventory/stock_item', 'product_id = entity_id', array('qty'));
        $stock->load();
        
        foreach($stock as $item){
            if((float)$item->getQty() <= $minQty){
                $results['data'][$item->getSku()] = (float)$item->getQty();
            }
        }
        
        $results['runTime'] = microtime(true) - $startTime;
        
        return $results;
    }

}