<?php
/**
 * Order Monitor
 *
 * @category    Ordermonitor
 * @package     Ordermonitor_Agent
 * @author      Digital Operative <codemaster@digitaloperative.com>
 * @copyright   Copyright (C) 2014 Digital Operative
 * @license     http://www.ordermonitor.com/license
 */
class Ordermonitor_Agent_Model_Monitor extends Mage_Core_Model_Abstract
{
    const ORDER_MONITOR_DATE_FORMAT = 'Y-m-d H:i:s';

    /**
     * Gets Monitor data for the given time period for the specified stores
     *
     * @param date/time $start start date
     * @param date/time $end end date
     * @param array $storeIds integer array of store ids
     * @param array $params array of parameters to determine what data to get
     * @return array monitor data for the time period
     */
    public function getOrderInfo($start, $end, $storeIds = array(0), $params = array())
    {
        $default = array(
            'getOrderTotals'  => true, 
            'getMinMaxPrices' => false, 
            'customerGroupId' => ''
            );
        
        $params = array_merge($default, $params);
        
        $startTime = microtime(true);
        $debug     = Mage::helper('ordermonitor_agent')->getOmDebugFlag();

        $startOrderDate = date(self::ORDER_MONITOR_DATE_FORMAT, $start);
        $endOrderDate   = date(self::ORDER_MONITOR_DATE_FORMAT, $end);

        $storeList = implode(',', $storeIds);

        $orders = Mage::getModel('sales/order')
            ->getCollection()
            ->addFieldToSelect(
                array(
                    'increment_id',
                    'store_id',
                    'created_at',
                    'total_qty_ordered',
                    'status',
                    'base_grand_total',
                    'base_subtotal',
                    'base_shipping_amount',
                    'base_tax_amount',
                    'shipping_method',
                    'coupon_code',
                    'base_discount_amount',
                    'total_item_count',
                    'customer_id',
                    'weight',
                    'customer_email'
                )
            )
            ->addAttributeToFilter('created_at', array('gteq' => $startOrderDate))
            ->addAttributeToFilter('created_at', array('lteq' => $endOrderDate));
        
        if(!empty($params['customerGroupId'])){
            $orders->addAttributeToFilter('customer_group_id', array('eq' => $params['customerGroupId']));
        }
        
        if ($storeList != 0) {
            $orders->addAttributeToFilter('store_id', array('in' => $storeIds));
        }

        $orders->load();

        $results['info']['debug'] = $debug;

        $results['info']['startDate']       = $startOrderDate;
        $results['info']['endDate']         = $endOrderDate;
        $results['info']['storeId']         = $storeList;
        $results['info']['runTime']         = 0;
        $results['info']['moduleVersion']   = Mage::helper('ordermonitor_agent')->getOmVersion($storeIds[0]);
        $results['info']['platform']        = 'Magento';
        $results['info']['platformVersion'] = Mage::getVersion();
        $results['info']['baseCurrency']    = Mage::app()->getStore($storeIds[0])->getCurrentCurrencyCode();

        // orders and items
        $results['info']['orders']      = $orders->getSize();
        $results['info']['items']       = 0;
        $results['info']['uniqueItems'] = 0;
        $results['info']['weight']      = 0;

        // taxes and free shipping
        $results['info']['taxedOrders']        = 0;
        $results['info']['freeShippingOrders'] = 0;

        // revenue totals
        $results['info']['grandTotal']             = 0;
        $results['info']['subTotal']               = 0;
        $results['info']['discountedOrdersTotal']  = 0;
        $results['info']['taxedOrdersTotal']       = 0;
        $results['info']['guestOrdersTotal']       = 0;
        $results['info']['accountOrdersTotal']     = 0;
        $results['info']['newAccountOrdersTotal']  = 0;

        // items
        $results['info']['itemsMinPrice'] = 0;
        $results['info']['itemsMaxPrice'] = 0;

        // carts
        $results['info']['newCarts']           = 0;
        $results['info']['updatedCarts']       = 0;
        $results['info']['newCartsActive']     = 0;
        $results['info']['updatedCartsActive'] = 0;

        // order value items
        $results['info']['shippingAmount'] = 0;
        $results['info']['discountAmount'] = 0;
        $results['info']['taxAmount']      = 0;

        // discounts
        $results['info']['coupons']          = 0;
        $results['info']['discounts']        = 0;
        $results['info']['discountsMaxPerc'] = 0;
        $results['info']['couponCodes']      = array();
        $results['info']['discountsPercSum'] = 0;

        // checkout methods
        $results['info']['checkoutGuest']      = 0;
        $results['info']['checkoutAccount']    = 0;
        $results['info']['checkoutNewAccount'] = 0;

        // status and shipping
        $results['info']['status']          = array();
        $results['info']['shippingMethod']  = array();
        $results['info']['itemTotals']      = array();
        $results['info']['stockAlerts']     = array();

        $results['info']['itemsMinPrice'] = 0;
        $results['info']['itemsMaxPrice'] = 0;

        // get item price ranges
        if ($params['getMinMaxPrices'] === true) {
            $itemPrices = $this->getItemPriceRanges($startOrderDate, $endOrderDate, $storeIds);

            if (isset($itemPrices['max_base_price'])) {
                $results['info']['itemsMinPrice'] = (double) $itemPrices['min_base_price'];
                $results['info']['itemsMaxPrice'] = (double) $itemPrices['max_base_price'];
            }
        }

        if ($params['getOrderTotals'] === true) {
            foreach ($orders as $order) {
                $results['info']['grandTotal']     += (double)$order->getBaseGrandTotal();
                $results['info']['subTotal']       += (double)$order->getBaseSubtotal();
                $results['info']['shippingAmount'] += (double)$order->getBaseShippingAmount();
                $results['info']['uniqueItems']    += (int)$order->getTotalItemCount();
                $results['info']['items']          += (int)$order->getTotalQtyOrdered();
                $results['info']['weight']         += (double)$order->getWeight();
                $results['info']['taxAmount']      += (double)$order->getBaseTaxAmount();
                $results['info']['discountAmount'] += (double)($order->getBaseDiscountAmount() * -1);

                if ((double)$order->getBaseTaxAmount() > 0) {
                    $results['info']['taxedOrders']++;
                    $results['info']['taxedOrdersTotal'] += (double)$order->getBaseSubtotal();
                }

                if ((double)$order->getBaseShippingAmount() == 0) {
                    $results['info']['freeShippingOrders']++;
                }

                if (!is_null($order->getCouponCode())) {
                    $results['info']['coupons']++;

                    $coupondCode = strtoupper(trim($order->getCouponCode()));

                    if (!isset($results['info']['couponCodes'][$coupondCode])) {
                        // initialize
                        $results['info']['couponCodes'][$coupondCode] = 0;
                    }
                    $results['info']['couponCodes'][$coupondCode]++;
                }

                if ((double) ($order->getBaseDiscountAmount() * -1) > 0) {
                    $results['info']['discounts']++;
                    $results['info']['discountedOrdersTotal'] += (double)$order->getBaseSubtotal();

                    $orderPercDiscount = round(((double)($order->getBaseDiscountAmount() * -1))/((double)$order->getBaseSubtotal()) * 100, 2);
                    
                    $results['info']['discountsPercSum'] += (double)$orderPercDiscount;

                    if ($orderPercDiscount > $results['info']['discountsMaxPerc']) {
                        $results['info']['discountsMaxPerc'] = $orderPercDiscount;
                    }
                }

                if (is_null($order->getCustomerId())) {
                    $results['info']['checkoutGuest']++;
                    $results['info']['guestOrdersTotal'] += (double)$order->getBaseGrandTotal();
                } else {
                    $results['info']['checkoutAccount']++;
                    $results['info']['accountOrdersTotal'] += (double)$order->getBaseGrandTotal();

                    $customerData = Mage::getModel('customer/customer')->load($order->getCustomerId());

                    if ($customerData->getCreatedAt() >= $startOrderDate) {
                        $results['info']['checkoutNewAccount']++;
                        $results['info']['newAccountOrdersTotal'] += (double)$order->getBaseGrandTotal();
                    }
                }

                if (!isset($results['info']['status'][$order->getStatus()])) {
                    // initialize the status
                    $results['info']['status'][$order->getStatus()] = 0;
                }

                $results['info']['status'][$order->getStatus()]++;

                if (!isset($results['info']['shippingMethod'][$order->getShippingMethod()])) {
                    // initialize the method
                    $results['info']['shippingMethod'][$order->getShippingMethod()] = 0;
                }

                $results['info']['shippingMethod'][$order->getShippingMethod()]++;
            }
        }

        $results['info']['runTime'] = microtime(true) - $startTime;

        return $results;
    }

    /**
     * Get validation hash from username and key
     *
     * @return string hashed value of username and key
     */
    public function getHash()
    {
        $hash = '';

        $omKey      = Mage::helper('ordermonitor_agent')->getOmKey();
        $omUsername = Mage::helper('ordermonitor_agent')->getOmUsername();

        if (!empty($omKey) && !empty($omUsername)) {
            $hash = md5($omKey . $omUsername);
        }

        return $hash;
    }

    /**
     * Gets the high and low item price for the items sold in the given range
     *
     * @param date/time $start start date
     * @param date/time $end end date
     * @param array $storeIds array of store ids
     * @return array min and max item price
     */
    public function getItemPriceRanges($start, $end, $storeIds = array(0))
    {

        $items = Mage::getModel('sales/order_item')
            ->getCollection()
            ->addAttributeToFilter('created_at', array('gteq' => $start))
            ->addAttributeToFilter('created_at', array('lteq' => $end))
            ->addAttributeToFilter('parent_item_id', array('null' => true));

        if ($storeIds[0] != 0) {
            $items->addAttributeToFilter('store_id', array('in' => $storeIds));
        }

        $items->getSelect()
            ->reset(Zend_Db_Select::COLUMNS)
            ->columns(array(
                'MAX(base_price) as max_base_price',
                'MIN(base_price) as min_base_price'
            ));

        return $items->getFirstItem()->toArray();
    }

    /**
     * Get a list of stores and currencies
     *
     * @return array of websites, stores, ids, names, currencies and orders
     */
    public function getStores()
    {
        $data = array();
        $now = time();

        foreach (Mage::app()->getWebsites() as $website) {
            $data[$website->getWebsiteId()]['name'] = $website->getName();
            $data[$website->getWebsiteId()]['currency'] = $website->getBaseCurrencyCode();
            $data[$website->getWebsiteId()]['timezone'] = $website->getConfig('general/locale/timezone');

            foreach ($website->getStores() as $store) {
                $data[$website->getWebsiteId()]['stores'][] = array(
                    'storeId' => $store->getStoreId(),
                    'storeName' => $store->getName(),
                    'orders30Days' => $this->getThirtyDaysOrders($store->getStoreId(), $now)
                );
            }
        }

        return $data;
    }

    /**
     * Check store ids to make sure they are numeric
     *
     * @param array $storeIds array of store ids
     * @return boolean
     */
    public static function storeIdsOk($storeIds)
    {
        $idsOk = true;

        foreach ($storeIds as $storeId) {
            if (!is_numeric($storeId)) {
                $idsOk = false;
                break;
            }
        }

        return $idsOk;
    }

    /**
     * Gets a list or skus and the total quantity and cost for the time period
     *
     * @param date/time $start start date
     * @param date/time $end end date
     * @param array $storeIds array of integers
     * @return array array of items, quantity and sales
     */
    public function getItemTotals($start, $end, $storeIds = array(0), $skus = array(), $limit = 100)
    {
        $startTime = microtime(true);

        $startOrderDate = date(self::ORDER_MONITOR_DATE_FORMAT, $start);
        $endOrderDate   = date(self::ORDER_MONITOR_DATE_FORMAT, $end);

        $items = Mage::getModel('sales/order_item')
            ->getCollection()
            ->addAttributeToFilter('created_at', array('gteq' => $startOrderDate))
            ->addAttributeToFilter('created_at', array('lteq' => $endOrderDate))
            ->addAttributeToFilter('parent_item_id', array('null' => true));

        if ($storeIds[0] != 0) {
            $items->addAttributeToFilter('store_id', array('in' => $storeIds));
        }

        if (count($skus) > 0) {
            $items->addAttributeToFilter('sku', array('in' => $skus));
        }

        $items->getSelect()
            ->reset(Zend_Db_Select::COLUMNS)
            ->columns(array(
                'sku',
                'name',
                'store_id',
                'SUM(qty_ordered) as ordered',
                'SUM(base_row_total) as total',
                'SUM(base_discount_amount) as discount',
            ))
            ->order('ordered DESC')
            ->group('sku')
            ->limit($limit);

        $totals = $items->toArray();
        
        $totals['runTime'] = microtime(true) - $startTime;

        return $totals;
    }

    /**
     * Get the current module and Magento version numbers
     *
     * @return array module and magento version
     */
    public function getVersions()
    {
        $info = array(
            'moduleVersion' => Mage::helper('ordermonitor_agent')->getOmVersion(),
            'platformVersion' => Mage::getVersion()
        );

        return $info;
    }
    
    /**
     * Get a list of all the customer groups and id's
     * @return array customer group id as key and group code as value
     */
    public function getCustomerGroupsList()
    {
        $customerGroup = new Mage_Customer_Model_Group();
        $allGroups = $customerGroup->getCollection()->toArray();
        
        foreach ($allGroups['items'] as $group) {
            $results[] = array('groupId' => $group['customer_group_id'],  'groupCode' => $group['customer_group_code']);
        }
        
        return $results;
    }

    /**
     * Get the count of new and updated carts
     *
     * @param date/time $start start date
     * @param date/time $end end date
     * @param array $storeIds array of integers
     * @return array count of new carts and updated carts
     */
    public function getCartInfo($start, $end, $storeIds = array(0))
    {
        $startTime = microtime(true);

        $results = array();

        $startOrderDate = date(self::ORDER_MONITOR_DATE_FORMAT, $start);
        $endOrderDate   = date(self::ORDER_MONITOR_DATE_FORMAT, $end);

        //Carts created
        $newCarts = Mage::getModel('sales/quote')
            ->getCollection()
            ->addFieldToFilter('created_at', array('gteq' => $startOrderDate))
            ->addFieldToFilter('created_at', array('lteq' => $endOrderDate));

        if ($storeIds[0] != 0) {
            $newCarts->addFieldToFilter('store_id', array('in' => $storeIds));
        }

        $newCarts->getSelect()
            ->reset(Zend_Db_Select::COLUMNS)
            ->columns(array('sum(is_active) as cartsCreatedActive'))
            ->columns(array('count(entity_id) as cartsCreated'));

        $newCartsCount = $newCarts->getFirstItem()->toArray();

        //Carts updated
        $updatedCarts = Mage::getModel('sales/quote')
            ->getCollection()
            ->addFieldToFilter('created_at', array('lt' => $startOrderDate))
            ->addFieldToFilter('updated_at', array('gteq' => $startOrderDate))
            ->addFieldToFilter('updated_at', array('lteq' => $endOrderDate));

        if ($storeIds[0] != 0) {
            $updatedCarts->addFieldToFilter('store_id', array('in' => $storeIds));
        }

        $updatedCarts->getSelect()
            ->reset(Zend_Db_Select::COLUMNS)
            ->columns(array('sum(is_active) as cartsUpdatedActive'))
            ->columns(array('count(entity_id) as cartsUpdated'));

        $updatedCartsCount = $updatedCarts->getFirstItem()->toArray();

        $results['data'] = array(
            'newCarts'           => (int)$newCartsCount['cartsCreated'],
            'newCartsActive'     => (int)$newCartsCount['cartsCreatedActive'],
            'updatedCarts'       => (int)$updatedCartsCount['cartsUpdated'],
            'updatedCartsActive' => (int)$updatedCartsCount['cartsUpdatedActive']
        );

        $results['runTime'] = microtime(true) - $startTime;

        return $results;
    }

    /**
     * Get the count of total orders for the last 30 days
     *
     * @param date/time $end end date
     * @param array $storeIds array of integers
     * @return int count of orders
     */
    public function getThirtyDaysOrders($storeId, $now)
    {
        $thirtyDays = 2592000;

        $startOrderDate = date(self::ORDER_MONITOR_DATE_FORMAT, $now - $thirtyDays);
        $endOrderDate   = date(self::ORDER_MONITOR_DATE_FORMAT, $now);

        $orders = Mage::getModel('sales/order')
            ->getCollection()
            ->addFieldToFilter('created_at', array('gteq' => $startOrderDate))
            ->addFieldToFilter('created_at', array('lteq' => $endOrderDate))
            ->addFieldToFilter('store_id', array('eq' => $storeId));

        $orders->getSelect()
            ->reset(Zend_Db_Select::COLUMNS)
            ->columns(array('count(entity_id) as totalOrders'));

        $results = $orders->getFirstItem()->toArray();

        return (int)$results['totalOrders'];
    }
    
    /**
     * Get the totals to calculate customer lifetime value
     *
     * @param date/time $end end date
     * @param array $storeIds array of integers
     * @return array subtotal all orders, items and numbers of customers
     */
    public function getCustomerTotals($start, $end, $storeIds = array(0), $time = 'all')
    {
        $startTime = microtime(true);
        
        $startOrderDate = date(self::ORDER_MONITOR_DATE_FORMAT, $start);
        $endOrderDate   = date(self::ORDER_MONITOR_DATE_FORMAT, $end);

        $items = Mage::getModel('sales/order')
            ->getCollection()
            ->addAttributeToFilter('created_at', array('lteq' => $endOrderDate));
        
        if($time != 'all'){
            $items->addFieldToFilter('created_at', array('gteq' => $startOrderDate));
        }

        if ($storeIds[0] != 0) {
            $items->addAttributeToFilter('store_id', array('in' => $storeIds));
        }

        $items->getSelect()
            ->reset(Zend_Db_Select::COLUMNS)
            ->columns(array(
                'COUNT(DISTINCT(customer_email)) as customers',
                'COUNT(increment_id) as orders',
                'SUM(base_subtotal) as subTotal',
                'SUM(base_grand_total) as grandTotal',
                'SUM(total_qty_ordered) as totalQty',
            ));
            
        $totals = $items->toArray();
        
        $totals['runTime'] = microtime(true) - $startTime;

        return $totals;
    }
    
}
