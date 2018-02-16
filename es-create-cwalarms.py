#!/usr/bin/env python
"""
Given the name of an Amazon Elasticsearch Service cluster, create the set of recommended CloudWatch alarms.

Naming convention for the alarms are: {Environment}-{domain}-{MetricName}-alarm

Requires the following permissions:  
* create CloudWatch alarms
        (per http://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/permissions-reference-cw.html )
        cloudwatch:DescribeAlarms
        cloudwatch:DescribeAlarmsForMetric
        cloudwatch:EnableAlarmActions | DisableAlarmActions (depending on options chosen)     	
        cloudwatch:PutMetricAlarm       
        ... The managed policy CloudWatchFullAccess provides the needed permissions.        

* To check that free space is appropriately defined, also need to be able to check the E/S cluster definitions.

        
Expects the following parameters:
env               environment; is used in the Alarm name only. Default: Test
clusterName       Amazon Elasticsearch Service domain name on which the alarms are to be created
clientId          the account Id of the owning AWS account (needed for CloudWatch alarm dimension)
alarmActions      list of SNS arns to be notified when the alarm is fired 
free              minimum amount of free storage to assign, if no other information is available

@author Veronika Megler
@date August 2017

"""

from __future__ import print_function # Python 2/3 compatibility

# Need to: pip install elasticsearch; boto3; requests_aws4auth; requests
# First: import standard modules
import string
import json
import time
from datetime import datetime
import sys
import os
import logging
import traceback
import boto3
import argparse
import ast
import collections

DEFAULT_REGION = 'us-east-1'
DEFAULT_SNSTOPIC = "sendnotification"

Alarm = collections.namedtuple('Alarm', ['metric', 'stat', 'period',  'eval_period', 'operator', 'threshold', 'alarmAction'])

# Amazon Elasticsearch Service settings 
ES_NAME_SPACE = 'AWS/ES'    # set for these Amazon Elasticsearch Service alarms
# The following table lists instance types with instance storage, for free storage calculations. 
# It must be updated when instance definitions change
# See: https://aws.amazon.com/elasticsearch-service/pricing/ , select your region
# Definitions are in GB
DISK_SPACE = {"r3.large.elasticsearch": 32,
    "r3.xlarge.elasticsearch":	80,
    "r3.2xlarge.elasticsearch":	160,
    "r3.4xlarge.elasticsearch":	320,
    "r3.8xlarge.elasticsearch":	640,
    "m3.medium.elasticsearch":	4,
    "m3.large.elasticsearch":	32,
    "m3.xlarge.elasticsearch":	80,
    "m3.2xlarge.elasticsearch":	160, 
    "i2.xlarge.elasticsearch":	800,
    "i2.2xlarge.elasticsearch":	1600,
    "i3.large.elasticsearch":   475,
    "i3.xlarge.elasticsearch":  950,
    "i3.2xlarge.elasticsearch": 1900,
    "i3.4xlarge.elasticsearch": 3800,
    "i3.8xlarge.elasticsearch": 7600,
    "i3.16xlarge.elasticsearch": 15200
    }
    
MIN_ES_FREESPACE = 2048.0  # default amount of free space (in MB). ALSO minimum set by AWS ES
MIN_ES_FREESPACE_PERCENT = .20    # Required minimum 20% free space
DEFAULT_ES_FREESPACE = MIN_ES_FREESPACE  

LOG_LEVELS = {'CRITICAL': 50, 'ERROR': 40, 'WARNING': 30, 'INFO': 20, 'DEBUG': 10}

def init_logging():
    # Setup logging because debugging with print can get ugly.
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logging.getLogger("boto3").setLevel(logging.WARNING)
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('nose').setLevel(logging.WARNING)

    return logger

def setup_local_logging(logger, log_level = 'INFO'):
    # Set the Logger so if running locally, it will print out to the main screen.
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s',datefmt='%Y-%m-%dT%H:%M:%SZ'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    if log_level in LOG_LEVELS:
        logger.setLevel(LOG_LEVELS[log_level])
    else:
        logger.setLevel(LOG_LEVELS['INFO'])

    return logger

def set_log_level(logger, log_level = 'INFO'):
    # There is some stuff that needs to go here.
    if log_level in LOG_LEVELS:
        logger.setLevel(LOG_LEVELS[log_level])
    else:
        logger.setLevel(LOG_LEVELS['INFO'])

    return logger

def convert_unicode(data):
    '''
    Takes a unicode input, and returns the same as utf-8
    '''
    if isinstance(data, basestring):
        return str(data)
    elif isinstance(data, collections.Mapping):
        return dict(map(convert_unicode, data.iteritems()))
    elif isinstance(data, collections.Iterable):
        return type(data)(map(convert_unicode, data))
    #else:
    return data       

def str_convert_unicode(data):   
    return str(convert_unicode(data))
    
def get_default_alarm_actions(region, account, snstopic):
    # A default alarmActions can be hardcoded, to allow for easier standardization.
    alarmActions = ["arn:aws:sns:" + str(region) + ":" + str(account) + ":" + str(snstopic)]
    return alarmActions    

def get_args():
    """
    Parse command line arguments and populate args object.
    The args object is passed to functions as argument

    Returns:
        object (ArgumentParser): arguments and configuration settings
    """
    try:
        currentAccount = boto3.client('sts').get_caller_identity().get('Account')   
    except Exception as e:     # e.g.: botocore.exceptions.EndpointConnectionError
        logger.critical(str(e))
        logger.critical("Exiting.")
        sys.exit()
    parser = argparse.ArgumentParser(description = 'Create a set of recommended CloudWatch alarms for a given Amazon Elasticsearch Service domain.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)  
    parser.add_argument('-n', '--notify', nargs='+', required = False, default=[],
        help = "List of CloudWatch alarm actions; e.g. ['arn:aws:sns:xxxx']")        
    parser.add_argument("-c", "--cluster", required = True, type = str, help = "Amazon Elasticsearch Service domain name (e.g., testcluster1)")
    parser.add_argument("-a", "--account", required = False, type = int, default=currentAccount,
        help = "AWS account id of the owning account (needed for metric dimension).")
    parser.add_argument("-e", "--env", required = False, type = str, default = "Test", 
        help = "Environment (e.g., Test, or Prod). Prepended to the alarm name.")    
    parser.add_argument("-f", "--free", required = False, type = float, default=DEFAULT_ES_FREESPACE, 
        help = "Minimum free storage (MB) on which to alarm")
    parser.add_argument("-p", "--profile", required = False, type = str, default='default',
        help = "IAM profile name to use")
    parser.add_argument("-r", "--region", required = False, type = str, default=DEFAULT_REGION, help = "AWS region for the cluster.")
    
    if len(sys.argv) == 1:
        parser.error('Insufficient arguments provided. Exiting for safety.')
        logging.critical("Insufficient arguments provided. Exiting for safety.")
        sys.exit()
    args = parser.parse_args()
    # Reset minimum allowable, if less than AWS ES min
    if args.free < MIN_ES_FREESPACE:
        logger.info("Freespace of " + str(args.free) + " is less than the minimum for AES of " + str(MIN_ES_FREESPACE) + ". Setting to " + str(MIN_ES_FREESPACE))
        args.free = MIN_ES_FREESPACE
    args.prog = parser.prog
    
    if args.notify == []:
        args.notify = get_default_alarm_actions(args.region,args.account,DEFAULT_SNSTOPIC) 
    logger.info("Starting at " + str(datetime.utcnow()) + ". Using parameters: " + str(args))
    return args

def calc_storage(b3session, domainStatus, wantesfree):
    # Calculate the amount of storage the free space alarm requires
    esfree = float(wantesfree)   # Start with given desired free storage amount
    ebs = False
    if not 'ElasticsearchClusterConfig' in domainStatus:
        logger.error("No ElasticsearchClusterConfig available. Setting desired storage to default: " + str(esfree))
        return esfree
    clusterConfig = domainStatus['ElasticsearchClusterConfig'] 
    is_ebs_enabled = 'EBSOptions' in domainStatus and domainStatus['EBSOptions']['EBSEnabled']
    if is_ebs_enabled:
        ebsOptions = domainStatus['EBSOptions']
        iops = "No Iops"
        if "Iops" in ebsOptions:
            iops = str(ebsOptions['Iops']) + " Iops"
        totalStorage = int(clusterConfig['InstanceCount']) * int(ebsOptions['VolumeSize']) * 1024   # Convert to MB
        logger.info(' '.join(["EBS enabled:", str(ebsOptions['EBSEnabled']), "type:", str(ebsOptions['VolumeType']), "size (GB):", str(ebsOptions['VolumeSize']), str(iops), str(totalStorage), " total storage (MB)"]))
        ebs = True
        esfree = float(int(float(totalStorage) * MIN_ES_FREESPACE_PERCENT))
    else:
        logger.warning("EBS not in use. Using instance storage only.")
        if clusterConfig['InstanceType'] in DISK_SPACE:
            esfree = DISK_SPACE[clusterConfig['InstanceType']] * 1024 * MIN_ES_FREESPACE_PERCENT * clusterConfig['InstanceCount']
            logger.info("Instance storage definition found for:", DISK_SPACE[clusterConfig['InstanceType']], "; free storage calced to:", esfree)
        else:
            # InstanceType not found in DISK_SPACE. What's going on? (some instance types change to/from EBS, over time, it seems)
            logger.warning(clusterConfig['InstanceType'] + " is using instance storage, but definition of its disk space is not available.")
    logger.info("Desired free storage set to (in MB): " + str(esfree)) 
    return esfree
    
###############################################################################
# 
# MAIN
#
###############################################################################    
def main():
    startTime = datetime.utcnow()
    print("Starting ... at {}".format(startTime))
    
    global logger
    logger = init_logging()
    os.environ['log_level'] = os.environ.get('log_level', "INFO")

    logger = setup_local_logging(logger, os.environ['log_level'])

    event = {'log_level': 'INFO'}
    os.environ['AWS_REGION'] = os.environ.get('AWS_REGION', DEFAULT_REGION)
    
    args = get_args()
    theAlarmAction = get_default_alarm_actions(args.region, args.account, DEFAULT_SNSTOPIC) if args.notify is None else args.notify
    esDomain = args.cluster
    b3session = boto3.Session(profile_name=args.profile, region_name=args.region)

    # Get current ES config details
    esclient = b3session.client("es")
    response = esclient.describe_elasticsearch_domain(DomainName=esDomain)
    if 'DomainStatus' not in response:
        # For whatever reason, didn't get a response from this domain. 
        logger.error("No domainStatus response received from domain " + domain + "; no alarms created")  
        return   

    domainStatus = response['DomainStatus']
    
    # The following array specifies the statistics we wish to create for each Amazon ES cluster. 
    # The stats are selected per the following documentation:
    #  http://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-managedomains.html#es-managedomains-cloudwatchmetrics
    # Array format:
    # (MetricName, Statistic, Period, EvaluationPeriods  [int], ComparisonOperator, Threshold [float] )
    #       ComparisonOperator: 'GreaterThanOrEqualToThreshold'|'GreaterThanThreshold'|'LessThanThreshold'|'LessThanOrEqualToThreshold'
    esAlarms = [
        Alarm(metric='ClusterStatus.yellow', stat='Maximum', period=60, eval_period=5, operator='GreaterThanOrEqualToThreshold', threshold=1.0, alarmAction=theAlarmAction),
        Alarm(metric='ClusterStatus.red', stat='Maximum', period=60, eval_period=5, operator='GreaterThanOrEqualToThreshold', threshold=1.0, alarmAction=theAlarmAction),
        Alarm(metric='CPUUtilization', stat='Average', period=60, eval_period=5, operator='GreaterThanOrEqualToThreshold', threshold=80.0, alarmAction=theAlarmAction),
        Alarm(metric='JVMMemoryPressure', stat='Average', period=60, eval_period=5, operator='GreaterThanOrEqualToThreshold', threshold=85.0, alarmAction=theAlarmAction),
        Alarm(metric='ClusterIndexWritesBlocked', stat='Maximum', period=60, eval_period=5, operator='GreaterThanOrEqualToThreshold', threshold=1.0, alarmAction=theAlarmAction),
        Alarm(metric="FreeStorageSpace", stat="Minimum", period=60, eval_period=5, 
            operator="LessThanOrEqualToThreshold", threshold=float(calc_storage(b3session, domainStatus, args.free)), alarmAction=theAlarmAction )
        # OPTIONAL
        , Alarm(metric='AutomatedSnapshotFailure', stat='Maximum', period=60, eval_period=5, operator='GreaterThanOrEqualToThreshold', threshold=1.0, alarmAction=theAlarmAction)             
        ]
 
    if domainStatus['ElasticsearchClusterConfig']['DedicatedMasterEnabled']:
        # The following alarms apply for domains with dedicated master nodes.
        logger.info(esDomain + " has Dedicated Masters. Adding Master alarms.")
        esAlarms.append(Alarm(metric='MasterCPUUtilization', stat='Maximum', period=60, eval_period=5, operator='GreaterThanOrEqualToThreshold', threshold=80.0, alarmAction=theAlarmAction))
        esAlarms.append(Alarm(metric='MasterJVMMemoryPressure', stat='Maximum', period=60, eval_period=5, operator='GreaterThanOrEqualToThreshold', threshold=80.0, alarmAction=theAlarmAction))
        esAlarms.append(Alarm(metric='MasterReachableFromNode', stat='Maximum', period=60, eval_period=5, operator='LessThanOrEqualToThreshold', threshold=0.0, alarmAction=theAlarmAction))
            
    if "EncryptionAtRestOptions" in domainStatus and domainStatus["EncryptionAtRestOptions"]["Enabled"]:
        # The following alarms are available for domains with encryption at rest
        logger.info(' '.join([esDomain, "is using encryption - adding KMS key alarms. Key:", str_convert_unicode(domainStatus["EncryptionAtRestOptions"]["KmsKeyId"])]))
        esAlarms.append(Alarm(metric='KMSKeyError', stat='Maximum', period=60, eval_period=5, operator='GreaterThanOrEqualToThreshold', threshold=1.0, alarmAction=theAlarmAction))
        esAlarms.append(Alarm(metric='KMSKeyInaccessible', stat='Maximum', period=60, eval_period=5, operator='GreaterThanOrEqualToThreshold', threshold=1.0, alarmAction=theAlarmAction))
        
    # Unless you add the correct dimensions, the alarm will not correctly "connect" to the metric
    # How do you know what's correct? - at the bottom of http://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/es-metricscollected.html
    dimensions = [  {"Name": "DomainName", "Value": esDomain }, 
                    {"Name": "ClientId", "Value": str(args.account) }
                ]
    cwclient = b3session.client("cloudwatch", region_name=args.region)

    # For each alarm in the array, create the CloudWatch alarm for this cluster 
    # NOTE: If you specify an Action with an SNS topic in the wrong region, you'll get a message that you've chosen an invalid region 
    # on the put_metric_alarm.
    theAlarmAction = args.notify
    for esAlarm in esAlarms:
        alarmName = '-'.join([args.env, 'Elasticsearch', esDomain, esAlarm.metric, 'Alarm'])        
        response = cwclient.put_metric_alarm(
            AlarmName=alarmName,
            AlarmDescription=alarmName,
            #ActionsEnabled=True|False,
            #OKActions=['string'],
            AlarmActions=esAlarm.alarmAction,
            #InsufficientDataActions=['string'],
            MetricName=esAlarm.metric,
            Namespace=ES_NAME_SPACE,
            Statistic=esAlarm.stat,
            #ExtendedStatistic='string',
            Dimensions=dimensions,
            Period=esAlarm.period,            #Unit='Seconds'|'Microseconds'|'Milliseconds'|'Bytes'|'Kilobytes'|'Megabytes'|'Gigabytes'|'Terabytes'|'Bits'|'Kilobits'|'Megabits'|'Gigabits'|'Terabits'|'Percent'|'Count'|'Bytes/Second'|'Kilobytes/Second'|'Megabytes/Second'|'Gigabytes/Second'|'Terabytes/Second'|'Bits/Second'|'Kilobits/Second'|'Megabits/Second'|'Gigabits/Second'|'Terabits/Second'|'Count/Second'|'None',
            EvaluationPeriods=esAlarm.eval_period,
            Threshold=esAlarm.threshold,
            ComparisonOperator=esAlarm.operator
            #TreatMissingData='string',
            #EvaluateLowSampleCountPercentile='string'
        )
        logger.info("Created " + alarmName)        
    
    logger.info("Finished creating " + str(len(esAlarms)) + " alarms for domain " + esDomain + "!")




if __name__ == "__main__":
    main()
