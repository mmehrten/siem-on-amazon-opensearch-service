#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = "Copyright Amazon.com, Inc. or its affiliates. " "All Rights Reserved."
__version__ = "2.10.2a"
__license__ = "MIT-0"
__author__ = "Akihiro Nakajima"
__url__ = "https://github.com/aws-samples/siem-on-amazon-opensearch-service"

import json
import os
import re
import sys
import time
import urllib.parse
import warnings
from functools import lru_cache, wraps
import base64
import gzip
import json
import os
import time

import requests
from requests.exceptions import ConnectionError
import boto3
from aws_lambda_powertools import Logger, Metrics
from aws_lambda_powertools.metrics import MetricUnit
from opensearchpy import AuthenticationException, AuthorizationException

import siem
from siem import geodb, ioc, utils, xff

logger = Logger(stream=sys.stdout, log_record_order=["level", "message"])
logger.info(f"version: {__version__}")
logger.info(f"boto3: {boto3.__version__}")
warnings.filterwarnings("ignore", "No metrics to publish*")
metrics = Metrics()

SQS_SPLITTED_LOGS_URL = None
if "SQS_SPLITTED_LOGS_URL" in os.environ:
    SQS_SPLITTED_LOGS_URL = os.environ["SQS_SPLITTED_LOGS_URL"]
ES_HOSTNAME = utils.get_es_hostname()
SERVICE = ES_HOSTNAME.split(".")[2]
AOSS_TYPE = os.getenv("AOSS_TYPE", "")
docid_set = set()


def extract_logfile_from_s3(record):
    if "s3" in record:
        s3key = record["s3"].get("object", {}).get("key")
        s3bucket = record["s3"].get("bucket", {}).get("name")
    elif "detail" in record:
        s3key = record["detail"].get("object", {}).get("key")
        s3bucket = record["detail"].get("bucket", {}).get("name")
    elif "eventSourceARN" in record and "kinesis" in record["eventSourceARN"]:
        s3bucket = "kinesis"
        s3key = record["logGroup"].split("/")[-1]
    else:
        s3key = ""
        s3bucket = ""
    s3key = urllib.parse.unquote_plus(s3key, encoding="utf-8")

    if s3key and s3bucket:
        logger.structure_logs(append=True, s3_key=s3key, s3_bucket=s3bucket)
        logtype = utils.get_logtype_from_s3key(s3key, logtype_s3key_dict)
        logconfig = create_logconfig(logtype)
        client = s3_client

        if s3bucket in control_tower_log_bucket_list:
            if control_tower_s3_client:
                client = control_tower_s3_client
            else:
                logger.warning(
                    "es-loader doesn't have valid credential to "
                    "access the S3 bucket in Log Archive"
                )
                raise Exception(
                    f"Failed to download s3://{s3bucket}/{s3key} because of invalid credential"
                )
        elif s3bucket.startswith("aws-security-data-lake-"):
            if security_lake_s3_client:
                client = security_lake_s3_client
            else:
                logger.warning(
                    "es-loader doesn't have valid credential to "
                    "access the S3 bucket in Security Lake"
                )
                raise Exception(
                    f"Failed to download s3://{s3bucket}/{s3key} "
                    "because of invalid credential"
                )

        logfile = siem.LogS3(
            record, s3bucket, s3key, logtype, logconfig, client, sqs_queue
        )
    else:
        logger.warning("Skipped because there is no S3 object. Invalid input data")
        logger.info(record)
        return None

    return logfile


@lru_cache(maxsize=1024)
def get_value_from_etl_config(logtype, key, keytype=None):
    try:
        if keytype is None:
            value = etl_config[logtype][key]
        elif keytype == "bool":
            value = etl_config[logtype].getboolean(key)
        elif keytype == "int":
            value = etl_config[logtype].getint(key)
        elif keytype == "re":
            rawdata = etl_config[logtype][key]
            if rawdata:
                value = re.compile(rawdata)
            else:
                value = ""
        elif keytype == "list":
            temp = etl_config[logtype][key]
            if temp.startswith("["):
                value = [x.strip() for x in temp.strip("[|]").split(",")]
            else:
                value = temp.split()
        elif keytype == "list_json":
            temp = etl_config[logtype][key]
            if temp:
                value = json.loads(temp)
            else:
                value = []
        else:
            value = ""
    except KeyError:
        logger.exception("Can't find the key in logconfig")
        raise KeyError("Can't find the key in logconfig") from None
    except re.error:
        msg = f"invalid regex pattern for {key} of {logtype} in " "aws.ini/user.ini"
        logger.exception(msg)
        raise Exception(msg) from None
    except json.JSONDecodeError:
        msg = f"{key} of {logtype} section is invalid list style in " "aws.ini/user.ini"
        logger.exception(msg)
        raise Exception(msg) from None
    except Exception:
        logger.exception("unknown error in aws.ini/user.ini")
        raise Exception("unknown error in aws.ini/user.ini") from None
    return value


@lru_cache(maxsize=1024)
def create_logconfig(logtype):
    type_re = [
        "s3_key_ignored",
        "log_pattern",
        "multiline_firstline",
        "xml_firstline",
        "file_timestamp_format",
    ]
    type_int = ["max_log_count", "text_header_line_number", "ignore_header_line_number"]
    type_bool = ["via_cwl", "via_firelens", "ignore_container_stderr", "timestamp_nano"]
    type_list = [
        "base.tags",
        "clientip_xff",
        "container.image.tag",
        "dns.answers",
        "dns.header_flags",
        "dns.resolved_ip",
        "dns.type",
        "ecs",
        "static_ecs",
        "event.category",
        "event.type",
        "file.attributes",
        "host.ip",
        "host.mac",
        "ioc_domain",
        "ioc_ip",
        "observer.ip",
        "observer.mac",
        "process.args",
        "registry.data.strings",
        "related.hash",
        "related.hosts",
        "related.ip",
        "related.user",
        "renamed_newfields",
        "rule.author",
        "threat.tactic.id",
        "threat.tactic.name",
        "threat.tactic.reference",
        "threat.technique.id",
        "threat.technique.name",
        "threat.technique.reference",
        "threat.technique.subtechnique.id",
        "threat.technique.subtechnique.name",
        "threat.technique.subtechnique.reference",
        "tls.client.certificate_chain",
        "tls.client.supported_ciphers",
        "tls.server.certificate_chain",
        "user.roles",
        "vulnerability.category",
        "x509.alternative_names",
        "x509.alternative_names",
        "x509.issuer.country",
        "x509.issuer.locality",
        "x509.issuer.organization",
        "x509.issuer.organizational_unit",
        "x509.issuer.state_or_province",
        "x509.subject.common_name",
        "x509.subject.country",
        "x509.subject.locality",
        "x509.subject.organization",
        "x509.subject.organizational_unit",
        "x509.subject.state_or_province",
    ]
    type_list_json = ["timestamp_format_list"]
    logconfig = {}
    if logtype in ("unknown", "nodata"):
        return logconfig
    for key in etl_config[logtype]:
        if key in type_re:
            logconfig[key] = get_value_from_etl_config(logtype, key, "re")
        elif key in type_int:
            logconfig[key] = get_value_from_etl_config(logtype, key, "int")
        elif key in type_bool:
            logconfig[key] = get_value_from_etl_config(logtype, key, "bool")
        elif key in type_list:
            logconfig[key] = get_value_from_etl_config(logtype, key, "list")
        elif key in type_list_json:
            logconfig[key] = get_value_from_etl_config(logtype, key, "list_json")
        else:
            logconfig[key] = get_value_from_etl_config(logtype, key)
    if logconfig["file_format"] in ("xml",):
        logconfig["multiline_firstline"] = logconfig["xml_firstline"]
    if SERVICE == "aoss":
        logconfig["index_rotation"] = "aoss"
    if logtype in log_exclusion_patterns:
        logconfig["exclusion_patterns"] = log_exclusion_patterns[logtype]
    if logtype in exclusion_conditions:
        logconfig["exclusion_conditions"] = exclusion_conditions[logtype]

    return logconfig


def get_es_entries(logfile):
    """get opensearch entries.

    To return json to load OpenSearch Service, extract log, map fields to ecs
     fields and enrich ip addresses with geoip. Most important process.
    """
    # ETL対象のログタイプのConfigだけを限定して定義する
    logconfig = create_logconfig(logfile.logtype)
    # load custom script
    sf_module = utils.load_sf_module(logfile, logconfig, user_libs_list)

    logparser = siem.LogParser(
        logfile, logconfig, sf_module, geodb_instance, ioc_instance, xff_instance
    )
    for lograw, logdata, logmeta in logfile:
        logparser(lograw, logdata, logmeta)
        if logparser.is_ignored:
            logfile.excluded_log_count += 1
            if logparser.ignored_reason:
                logger.info(f"Skipped log because {logparser.ignored_reason}")
            continue
        indexname = utils.get_writable_indexname(logparser.indexname, READ_ONLY_INDICES)
        action_meta = {"index": {"_index": indexname, "_id": logparser.doc_id}}
        # logger.debug(logparser.json)
        yield [action_meta, logparser.json]

    del logparser


def check_es_results(results, total_count):
    duration = results["took"]
    success, error = 0, 0
    error_reasons = []
    count = total_count
    retry = False
    if not results["errors"]:
        success = len(results["items"])
    else:
        for result in results["items"]:
            count += 1
            if result["index"]["status"] >= 300:
                # status code
                # 200:OK, 201:Created
                # https://github.com/opensearch-project/OpenSearch/blob/1.3.0/server/src/main/java/org/opensearch/rest/RestStatus.java
                # https://github.com/opensearch-project/logstash-output-opensearch/blob/v1.2.0/lib/logstash/outputs/opensearch.rb#L32-L43
                if result["index"]["status"] in (400, 409):
                    # 400: BAD_REQUEST such as mapper_parsing_exception
                    # 409: CONFLICT
                    pass
                else:
                    # 403: FORBIDDEN such as index_create_block_exception,
                    #      disk_full
                    # 429: TOO_MANY_REQUESTS
                    # 503: SERVICE_UNAVAILABLE
                    retry = True
                error += 1
                error_reason = result["index"].get("error")
                error_reason["log_number"] = count
                if error_reason:
                    error_reasons.append(error_reason)
            else:
                success += 1

    return duration, success, error, error_reasons, retry


def bulkloads_into_opensearch(es_entries, collected_metrics):
    global es_conn
    global docid_set
    output_size, total_output_size = 0, 0
    total_count, success_count, error_count, es_response_time = 0, 0, 0, 0
    results = False
    putdata_list = []
    error_reason_list = []
    retry_needed = False
    filter_path = ["took", "errors", "items.index.status", "items.index.error"]
    docid_list = []
    for data in es_entries:
        if AOSS_TYPE == "TIMESERIES":
            docid = data[0]["index"].pop("_id")
            if docid in docid_set:
                continue
            docid_list.append(docid)
        action_meta = json.dumps(data[0])
        parsed_json = data[1]
        putdata_list.extend([action_meta, parsed_json])
        output_size += len(action_meta) + len(parsed_json)
        # es の http.max_content_length は t2 で10MB なのでデータがたまったらESにロード
        if output_size > 6000000:
            total_output_size += output_size
            try:
                results = es_conn.bulk(putdata_list, filter_path=filter_path)
            except (AuthorizationException, AuthenticationException) as err:
                logger.warning(
                    "AuthN or AuthZ Exception raised due to SigV4 issue. "
                    f"http_compress has been disabled. {err}"
                )
                es_conn = utils.create_es_conn(
                    awsauth, ES_HOSTNAME, http_compress=False
                )
                results = es_conn.bulk(putdata_list, filter_path=filter_path)
            es_took, success, error, error_reasons, retry = check_es_results(
                results, total_count
            )
            success_count += success
            error_count += error
            es_response_time += es_took
            output_size = 0
            total_count = success_count + error_count
            putdata_list = []
            if len(error_reasons):
                error_reason_list.extend(error_reasons)
            if retry:
                retry_needed = True
    if output_size > 0:
        total_output_size += output_size
        try:
            results = es_conn.bulk(putdata_list, filter_path=filter_path)
        except (AuthorizationException, AuthenticationException) as err:
            logger.warning(
                "AuthN or AuthZ Exception raised due to SigV4 issue. "
                f"http_compress has been disabled. {err}"
            )
            es_conn = utils.create_es_conn(awsauth, ES_HOSTNAME, http_compress=False)
            results = es_conn.bulk(putdata_list, filter_path=filter_path)
        # logger.debug(results)
        es_took, success, error, error_reasons, retry = check_es_results(
            results, total_count
        )
        success_count += success
        error_count += error
        es_response_time += es_took
        total_count = success_count + error_count
        if len(error_reasons):
            error_reason_list.extend(error_reasons)
        if retry:
            retry_needed = True
    if AOSS_TYPE == "TIMESERIES":
        for error_reason in reversed(error_reason_list):
            del docid_list[error_reason["log_number"] - 1]
        docid_set.update(docid_list)
    collected_metrics["total_output_size"] = total_output_size
    collected_metrics["total_log_load_count"] = total_count
    collected_metrics["success_count"] = success_count
    collected_metrics["error_count"] = error_count
    collected_metrics["es_response_time"] = es_response_time

    return collected_metrics, error_reason_list, retry_needed


def output_metrics(
    metrics,
    excluded_log_count,
    counted_log_count,
    s3obj_size,
    s3key,
    total_log_count,
    logtype,
    collected_metrics={},
    **kwargs,
):
    if not os.environ.get("AWS_EXECUTION_ENV"):
        return
    total_output_size = collected_metrics["total_output_size"]
    success_count = collected_metrics["success_count"]
    error_count = collected_metrics["error_count"]
    excluded_log_count = excluded_log_count
    counted_log_count = counted_log_count
    es_response_time = collected_metrics["es_response_time"]
    input_file_size = s3obj_size
    s3_key = s3key
    duration = int((time.perf_counter() - collected_metrics["start_time"]) * 1000) + 10
    total_log_count = total_log_count

    metrics.add_dimension(name="logtype", value=logtype)
    metrics.add_metric(
        name="InputLogFileSize", unit=MetricUnit.Bytes, value=input_file_size
    )
    metrics.add_metric(
        name="OutputDataSize", unit=MetricUnit.Bytes, value=total_output_size
    )
    metrics.add_metric(
        name="SuccessLogLoadCount", unit=MetricUnit.Count, value=success_count
    )
    metrics.add_metric(
        name="ErrorLogLoadCount", unit=MetricUnit.Count, value=error_count
    )
    metrics.add_metric(
        name="ExcludedLogCount", unit=MetricUnit.Count, value=excluded_log_count
    )
    metrics.add_metric(
        name="CountedLogCount", unit=MetricUnit.Count, value=counted_log_count
    )
    metrics.add_metric(
        name="TotalDurationTime", unit=MetricUnit.Milliseconds, value=duration
    )
    metrics.add_metric(
        name="EsResponseTime", unit=MetricUnit.Milliseconds, value=es_response_time
    )
    metrics.add_metric(name="TotalLogFileCount", unit=MetricUnit.Count, value=1)
    metrics.add_metric(
        name="TotalLogCount", unit=MetricUnit.Count, value=total_log_count
    )
    metrics.add_metadata(key="s3_key", value=s3_key)


def observability_decorator_switcher(func):
    if os.environ.get("AWS_EXECUTION_ENV"):

        @metrics.log_metrics
        @logger.inject_lambda_context(clear_state=True)
        @wraps(func)
        def decorator(*args, **kwargs):
            return func(*args, **kwargs)

        return decorator
    else:
        # local environment
        @wraps(func)
        def decorator(*args, **kwargs):
            return func(*args, **kwargs)

        return decorator


awsauth = utils.create_awsauth(ES_HOSTNAME)
es_conn = utils.create_es_conn(awsauth, ES_HOSTNAME)
if SERVICE == "es":
    DOMAIN_INFO = es_conn.info()
    logger.info(DOMAIN_INFO)
    READ_ONLY_INDICES = utils.get_read_only_indices(es_conn, awsauth, ES_HOSTNAME)
    logger.info(json.dumps({"READ_ONLY_INDICES": READ_ONLY_INDICES}))
elif SERVICE == "aoss":
    READ_ONLY_INDICES = ""
user_libs_list = utils.find_user_custom_libs()
etl_config = utils.get_etl_config()
utils.load_modules_on_memory(etl_config, user_libs_list)
logtype_s3key_dict = utils.create_logtype_s3key_dict(etl_config)
exclusion_conditions = utils.get_exclusion_conditions()

builtin_log_exclusion_patterns: dict = utils.make_exclude_own_log_patterns(etl_config)
csv_filename = utils.get_exclude_log_patterns_csv_filename(etl_config)
custom_log_exclusion_patterns: dict = utils.convert_csv_into_log_patterns(csv_filename)
log_exclusion_patterns: dict = utils.merge_log_exclusion_patterns(
    builtin_log_exclusion_patterns, custom_log_exclusion_patterns
)
# e.g. log_exclusion_patterns['cloudtrail'] = [pattern1, pattern2]

s3_session_config = utils.make_s3_session_config(etl_config)
s3_client = boto3.client("s3", config=s3_session_config)
sqs_queue = utils.sqs_queue(SQS_SPLITTED_LOGS_URL)

control_tower_log_buckets = os.environ.get("CONTROL_TOWER_LOG_BUCKETS", "")
control_tower_log_bucket_list = control_tower_log_buckets.replace(",", " ").split()
control_tower_role_arn = os.environ.get("CONTROL_TOWER_ROLE_ARN")
control_tower_role_session_name = os.environ.get("CONTROL_TOWER_ROLE_SESSION_NAME")
control_tower_s3_client = utils.get_s3_client_for_crosss_account(
    config=s3_session_config,
    role_arn=control_tower_role_arn,
    role_session_name=control_tower_role_session_name,
)

security_lake_log_buckets = os.environ.get("SECURITY_LAKE_LOG_BUCKETS", "")
security_lake_role_arn = os.environ.get("SECURITY_LAKE_ROLE_ARN")
security_lake_role_session_name = os.environ.get("SECURITY_LAKE_ROLE_SESSION_NAME")
security_lake_external_id = os.environ.get("SECURITY_LAKE_EXTERNAL_ID")
security_lake_s3_client = utils.get_s3_client_for_crosss_account(
    config=s3_session_config,
    role_arn=security_lake_role_arn,
    role_session_name=security_lake_role_session_name,
    external_id=security_lake_external_id,
)

geodb_instance = geodb.GeoDB(s3_session_config)
ioc_instance = ioc.DB(s3_session_config)
xff_instance = xff.DB(s3_session_config)
utils.show_local_dir()


@observability_decorator_switcher
def lambda_handler(event, context):
    main(event, context)
    return {"EventResponse": None}


def main(event, context):
    if "Records" in event:
        event_source = event["Records"][0].get("eventSource")
        error_code = event["Records"][0].get("messageAttributes", {}).get("ErrorCode")
        if event_source == "aws:s3":
            # s3 notification directly
            for record in event["Records"]:
                process_record(record)
        elif event_source == "aws:sqs" and error_code:
            # DLQ retrive
            for record in event["Records"]:
                main(json.loads(record["body"]), context)
        elif event_source == "aws:sqs":
            # s3 notification from SQS
            for record in event["Records"]:
                recs = json.loads(record["body"])
                if "Records" in recs:
                    # Control Tower
                    for record in recs["Records"]:
                        process_record(record)
                else:
                    # from sqs-splitted-log, Security Lake(via EventBridge)
                    process_record(recs)
        elif event_source == "aws:kinesis":
            # s3 notification from SQS
            collected_metrics = {"start_time": time.perf_counter()}
            total_metrics = {
                "excluded_log_count": 0,
                "counted_log_count": 0,
                "s3obj_size": 0,
                "s3key": "",
                "logtype": "",
                "total_log_count": 0,
                "error_logs_count": 0,
                "is_ignored": False,
                "ignored_reason": "",
            }
            to_publish = []
            for record in event["Records"]:
                data = unpack(record["kinesis"]["data"])
                # CONTROL_MESSAGE are sent by CWL to check if the subscription is reachable.
                # They do not contain actual data.
                if data["messageType"] == "DATA_MESSAGE":
                    common_data = {
                        "owner": data["owner"],
                        "logGroup": data["logGroup"],
                        "logStream": data["logStream"],
                        "eventSourceARN": record["eventSourceARN"],
                        "eventID": record["eventID"],
                        "approximateArrivalTimestamp": record["kinesis"][
                            "approximateArrivalTimestamp"
                        ],
                    }
                    for e in data["logEvents"]:
                        e.update(**common_data)
                        processed_records, log = process_record(e, publish=False)
                        if not to_publish:
                            logger.info(log.startmsg())
                        to_publish += processed_records
                        total_metrics["excluded_log_count"] += log.excluded_log_count
                        total_metrics["counted_log_count"] += log.counted_log_count
                        total_metrics["s3obj_size"] += log.s3obj_size
                        total_metrics["s3key"] = log.s3key
                        total_metrics["logtype"] = log.logtype
                        total_metrics["total_log_count"] += log.total_log_count
                        total_metrics["error_logs_count"] += log.error_logs_count
                        total_metrics["is_ignored"] = (
                            total_metrics["is_ignored"] or log.is_ignored
                        )
                        if total_metrics["is_ignored"]:
                            total_metrics["ignored_reason"] = log.ignored_reason
                        del log
            error_reason_list = load_os(to_publish, collected_metrics)
            log_metrics(
                total_metrics["error_logs_count"],
                total_metrics["is_ignored"],
                total_metrics["ignored_reason"],
                collected_metrics,
                error_reason_list,
            )
            output_metrics(
                metrics, collected_metrics=collected_metrics, **total_metrics
            )
        elif event["Records"][0].get("EventSource") == "aws:sns":
            # s3 notification from SNS
            for record in event["Records"]:
                recs = json.loads(record["Sns"]["Message"])
                for record in recs["Records"]:
                    process_record(record)
        else:
            # local execution
            for record in event["Records"]:
                process_record(record)
    elif (
        event.get("source") == "aws.s3" and event.get("detail-type") == "Object Created"
    ):
        # s3 notification from EventBridge
        record = {"s3": event["detail"]}
        process_record(record)


def unpack(encoded_data):
    return json.loads(gzip.decompress(base64.b64decode(encoded_data)))


def process_record(record, publish: bool = True):
    collected_metrics = {"start_time": time.perf_counter()}
    # S3からファイルを取得してログを抽出する
    logfile = extract_logfile_from_s3(record)
    if logfile is None:
        return None
    if publish:
        logger.info(logfile.startmsg())
    elif logfile.is_ignored:
        if hasattr(logfile, "ignored_reason") and logfile.ignored_reason:
            logger.warning(f"Skipped S3 object because {logfile.ignored_reason}")
        elif hasattr(logfile, "critical_reason") and logfile.critical_reason:
            logger.critical(f"Skipped S3 object because {logfile.critical_reason}")
        return None

    # 抽出したログからESにPUTするデータを作成する
    es_entries = get_es_entries(logfile)
    if publish:
        error_reason_list = load_os(es_entries, collected_metrics)
        output_metrics(
            metrics,
            collected_metrics=collected_metrics,
            excluded_log_count=logfile.excluded_log_count,
            counted_log_count=logfile.counted_log_count,
            s3obj_size=logfile.s3obj_size,
            s3key=logfile.s3key,
            logtype=logfile.logtype,
            total_log_count=logfile.total_log_count,
        )
        log_metrics(
            logfile.error_logs_count,
            logfile.is_ignored,
            logfile.ignored_reason,
            collected_metrics,
            error_reason_list,
        )
        del logfile
        return [], None
    return es_entries, logfile


def load_os(es_entries, collected_metrics):
    # 作成したデータをESにPUTしてメトリクスを収集する
    (collected_metrics, error_reason_list, retry_needed) = bulkloads_into_opensearch(
        es_entries, collected_metrics
    )
    if retry_needed:
        logger.error("Aborted. It may be retried")
    return error_reason_list


def log_metrics(
    error_logs_count, is_ignored, ignored_reason, collected_metrics, error_reason_list
):
    if error_logs_count > 0:
        collected_metrics["error_count"] += error_logs_count
    if is_ignored:
        logger.warning(f"Skipped S3 object because {ignored_reason}")
    elif collected_metrics["error_count"]:
        extra = None
        error_message = (
            f"{collected_metrics['error_count']} of logs "
            "were NOT loaded into OpenSearch Service"
        )
        if len(error_reason_list) > 0:
            extra = {"message_error": error_reason_list[:5]}
        logger.error(error_message, extra=extra)
    elif collected_metrics["total_log_load_count"] > 0:
        logger.info("All logs were loaded into OpenSearch Service")
    else:
        logger.warning("No entries were successed to load")


if __name__ == "__main__":
    import argparse
    import traceback
    from datetime import datetime, timezone
    from functools import partial
    from multiprocessing import Pool

    print(__version__)

    def check_args():
        parser = argparse.ArgumentParser(
            description="es-loader",
        )
        group = parser.add_mutually_exclusive_group(required=False)
        group.add_argument("-b", "--s3bucket", help="s3 bucket where logs are storeed")
        parser.add_argument(
            "-l",
            "--s3list",
            help=(
                "s3 object list which you want to load to "
                "OpenSearch Service. You can create the "
                "list by "
                '"aws s3 ls S3BUCKET --recursive"'
            ),
        )
        group.add_argument("-q", "--sqs", help="SQS queue name of DLQ")
        args = parser.parse_args()
        if args.s3bucket:
            if not args.s3list:
                print("You neee to provide s3 object list with -l")
                sys.exit("Exit")
        return args

    def create_event_from_s3list(s3bucket, s3list):
        with open(s3list) as f:
            for num, line_text in enumerate(f.readlines()):
                try:
                    dummy, dummy, dummy, s3key = line_text.split()
                except ValueError:
                    continue
                line_num = num + 1
                s3key = s3key
                event = {
                    "Records": [
                        {"s3": {"bucket": {"name": s3bucket}, "object": {"key": s3key}}}
                    ]
                }
                yield line_num, event, None

    def create_event_from_sqs(queue_name):
        sqs = boto3.resource("sqs")
        queue = sqs.get_queue_by_name(QueueName=queue_name)
        try_list = []
        while True:
            messages = queue.receive_messages(
                MessageAttributeNames=["All"],
                MaxNumberOfMessages=10,
                VisibilityTimeout=300,
                WaitTimeSeconds=1,
            )
            if messages:
                for msg in messages:
                    if msg.message_id not in try_list:
                        try_list.append(msg.message_id)
                        event = json.loads(msg.body)
                        if "Records" in event:
                            # from DLQ
                            pass
                        else:
                            # from aes-siem-sqs-splitted-logs
                            event = {"Records": [json.loads(msg.body)]}
                        yield msg.message_id, event, msg
            else:
                break

    def open_debug_log(outfile):
        error_log = outfile + ".error.log"
        error_debug_log = outfile + ".error_debug.log"
        finish_log = outfile + ".finish.log"
        f_err = open(error_log, "w")
        f_err_debug = open(error_debug_log, "w")
        f_finish = open(finish_log, "w")
        return f_err, f_err_debug, f_finish

    def close_debug_log(outfile, f_err, f_err_debug, f_finish):
        error_log = outfile + ".error.log"
        error_debug_log = outfile + ".error_debug.log"
        f_err.close()
        f_err_debug.close()
        f_finish.close()
        # print number of error
        err_count = sum([1 for _ in open(error_log)])
        if err_count > 0:
            print(
                f"{err_count} logs are not loaded to ES. See for details, "
                f"{error_debug_log}"
            )
        else:
            os.remove(error_debug_log)
            os.remove(error_log)

    def my_callback(*args, event=None, context=None, sqsmsg=None, f_finish=None):
        line = context["line"]
        s3_bucket = event["Records"][0]["s3"]["bucket"]["name"]
        s3_key = event["Records"][0]["s3"]["object"]["key"]
        f_finish.write(f"{line}\ts3://{s3_bucket}/{s3_key}\n")
        f_finish.flush()
        if sqsmsg:
            sqsmsg.delete()

    def my_err_callback(*args, event=None, context=None, f_err=None, f_err_debug=None):
        line = context["line"]
        s3_bucket = event["Records"][0]["s3"]["bucket"]["name"]
        s3_key = event["Records"][0]["s3"]["object"]["key"]
        now = datetime.now(timezone.utc)
        f_err.write(f"{now}\t{line}\t{s3_key}\n")
        f_err.flush()
        f_err_debug.write(f"{line}\ts3://{s3_bucket}/{s3_key}\n")
        f_err_debug.write(f"{args}\n")
        f_err_debug.flush()

    ###########################################################################
    # main logic
    ###########################################################################
    print("startting main logic on local shell")
    args = check_args()
    if args.s3list:
        outfile = args.s3list
        events = create_event_from_s3list(args.s3bucket, args.s3list)
    elif args.sqs:
        outfile = args.sqs + datetime.now(timezone.utc).strftime("-%Y%m%d_%H%M%S")
        events = create_event_from_sqs(args.sqs)
    else:
        outfile = "out"
        events = [
            (
                1,
                {
                    "Records": [
                        {
                            "kinesis": {
                                "kinesisSchemaVersion": "1.0",
                                "partitionKey": "c3a6c051-b213-47a2-bb5a-0af1f540e5b8",
                                "sequenceNumber": "49643993608893682057885874152240409682488743854371504178",
                                "data": "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",
                                "approximateArrivalTimestamp": 1698865785.322,
                            },
                            "eventSource": "aws:kinesis",
                            "eventVersion": "1.0",
                            "eventID": "shardId-000000000003:49643993608893682057885874152240409682488743854371504178",
                            "eventName": "aws:kinesis:record",
                            "invokeIdentityArn": "arn:aws-us-gov:iam::053633994311:role/dp-zwy2.iam.role.lambda.cloudwatch-dataprepper-processor",
                            "awsRegion": "us-gov-west-1",
                            "eventSourceARN": "arn:aws-us-gov:kinesis:us-gov-west-1:053633994311:stream/cloudtrail_agg_stream",
                        }
                    ]
                },
                "None",
            )
        ]
    f_err, f_err_debug, f_finish = open_debug_log(outfile)
    cpu_count = os.cpu_count()
    for line, event, sqs in events:
        lambda_handler(event, {"line": line})
    # with Pool(3 * cpu_count) as pool:
    #     results_pool = []
    #     for line, event, sqs in events:
    #         context = {'line': line}
    #         res = pool.apply_async(
    #             lambda_handler, (event, context),
    #             callback=partial(my_callback, event=event, context=context,
    #                              f_finish=f_finish, sqsmsg=sqs),
    #             error_callback=partial(my_err_callback, event=event,
    #                                    context=context, f_err=f_err,
    #                                    f_err_debug=f_err_debug))
    #         try:
    #             res.get()
    #         except Exception:
    #             f_err_debug.write(traceback.format_exc())
    #             print(traceback.format_exc())

    #     pool.close()
    #     pool.join()

    close_debug_log(outfile, f_err, f_err_debug, f_finish)
    print("INFO: Finishaed batch loading")
