<?php
/**
 * Order Monitor
 *
 * @category    Ordermonitor
 * @package     Ordermonitor_Agent
 * @author      Digital Operative <codemaster@digitaloperative.com>
 * @copyright   Copyright (C) 2016 Digital Operative
 * @license     http://www.ordermonitor.com/license
 */
class Ordermonitor_Agent_Model_Cron extends Mage_Core_Model_Abstract
{

    /**
     * Get the cron status for all jobs run in the last x days
     *
     * @param int $days
     * @return array list of jobs and status for each
     */
    public function getCronStatus($days = 3)
    {
        $window = 60 * 60 * 24 * (int) $days;
        $now = time();

        $results = array(
            'lookBackWindow' => $window,
            'lastComplete'   => $window,
            'jobsList'       => array(),
            'jobs'           => array()
        );

        $results['jobsList']     = $this->_getJobsList($window);
        $results['lastComplete'] = $this->_getLastCompleted($now, $window);

        foreach ($results['jobsList'] as $job) {
            $results['jobs'][$job] = $this->_getJobStatus($job, $now, $window);
        }

        return $results;
    }

    /**
     * Get the status and details for a cron kob
     *
     * @param $jobCode job code name
     * @return array array of jobs and status and times
     */
    private function _getJobStatus($jobCode, $time, $maxTime)
    {
        $results = array(
            'status' => '',
            'scheduled' => $maxTime,
            'executed'  => $maxTime,
            'finished'  => $maxTime,
        );

        $items = Mage::getModel('cron/schedule')
            ->getCollection()
            ->addFieldToFilter('job_code', array('eq' => $jobCode))
            ->addFieldToFilter('scheduled_at', array('lteq' => strftime('%Y-%m-%d %H:%M:00', $time)))
            ->setOrder('executed_at', 'DESC');

        $items->getSelect()
            ->reset(Zend_Db_Select::COLUMNS)
            ->columns(array('status', 'scheduled_at', 'executed_at', 'finished_at'))
            ->limit(1);

        $jobInfo = $items->getFirstItem()->setPageSize(1)->toArray();

        if (count($jobInfo) > 0) {
            $results['status']    = $jobInfo['status'];
            $results['scheduled'] = $time - strtotime($jobInfo['scheduled_at']);
            $results['executed']  = (is_null($jobInfo['executed_at']) ? $maxTime : $time - strtotime($jobInfo['executed_at']));
            $results['finished']  = (is_null($jobInfo['finished_at']) ? $maxTime : $time - strtotime($jobInfo['finished_at']));
        }

        return $results;
    }

    /**
     * Gets a list of all the jobs that have been scheduled in the last x days
     *
     * @param $window number of days to look for jobs
     * @param int $limit max number of jobs to pull
     * @return array of job codes
     */
    private function _getJobsList($window, $limit = 50)
    {
        $results = array();

        $items = Mage::getModel('cron/schedule')->getCollection()
            ->addFieldToFilter('scheduled_at', array('gt' => strftime('%Y-%m-%d %H:%M:00', time() - $window)));

        $items->getSelect()
            ->reset(Zend_Db_Select::COLUMNS)
            ->columns(array('job_code'))
            ->group('job_code')
            ->limit($limit);

        $jobs = $items->toArray();

        foreach ($jobs['items'] as $job) {
            $results[] = $job['job_code'];
        }

        return $results;
    }

    /**
     * Gets the number of seconds since a job ran successfully
     *
     * @param $time current time
     * @return string number of seconds
     */
    private function _getLastCompleted($time, $maxTime)
    {
        $items = Mage::getModel('cron/schedule')
            ->getCollection()
            ->addFieldToFilter('executed_at', array('lteq' => strftime('%Y-%m-%d %H:%M:00', $time)))
            ->addFieldToFilter('finished_at', array('neq' => 'NULL'))
            ->setOrder('finished_at', 'DESC');

        $items->getSelect()
            ->reset(Zend_Db_Select::COLUMNS)
            ->columns(array('status', 'scheduled_at', 'executed_at', 'finished_at'))
            ->limit(1);

        $jobInfo = $items->getFirstItem()->setPageSize(1)->toArray();

        return (!isset($jobInfo['finished_at']) || is_null($jobInfo['finished_at'] ) ? $maxTime : $time - strtotime($jobInfo['finished_at']));
    }
}